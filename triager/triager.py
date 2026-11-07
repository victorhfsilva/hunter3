#!/usr/bin/env python3
"""triager — correlate recon outputs, triage candidates and validate safely.

Fully non-interactive, timeboxed, resumable and guaranteed to terminate.
"""

from __future__ import annotations

import argparse
import os
import signal
import sys
import uuid
from pathlib import Path

from triager import discover, report, triage
from triager.discover import looks_like_sub
from triager.budget import Budget, BudgetExceeded, Watchdog
from triager.http import HttpClient, ScopeViolation
from triager.scope import ScopeError, load_targets
from triager.state import (
    atomic_write_text,
    load_json,
    new_root_state,
    safe_folder,
    utcnow,
)
from triager.validate import run_validation


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="triager.py",
        description="Correlaciona outputs de recon/scan, triagem e validação não destrutiva.",
        usage="python3 triager.py <pasta-de-outputs> [opções]",
    )
    parser.add_argument("outputs", help="Diretório com outputs de recon/scan")
    parser.add_argument("--targets", help="Hosts/URLs autorizados, separados por vírgula")
    parser.add_argument("--targets-file", help="Arquivo com 1 alvo por linha (# comentário)")
    parser.add_argument("--out", help="Raiz de saída (padrão: <outputs>/_analysis)")
    parser.add_argument("--split-dir", action="store_true", help="Cada subpasta de 1º nível = um subdomínio")
    parser.add_argument("--recon-only", action="store_true", help="Para após inventário + triagem")
    parser.add_argument("--resume", action="store_true", help="Retoma do state.json existente")
    parser.add_argument("--max-candidates", type=int, default=15, help="Candidatas validadas por execução")
    parser.add_argument("--max-minutes", type=float, default=20.0, help="Orçamento global de wall-clock")
    parser.add_argument("--per-target-max-minutes", type=float, default=None, help="Orçamento por subdomínio")
    parser.add_argument("--max-requests", type=int, default=200, help="Teto de requisições")
    parser.add_argument("--budget-scope", choices=("per-target", "global"), default="per-target")
    parser.add_argument("--max-total-requests", type=int, default=None, help="Teto absoluto de segurança")
    parser.add_argument("--file-max-seconds", type=float, default=60.0, help="Tempo máximo por arquivo")
    parser.add_argument("--file-max-mb", type=float, default=10.0, help="Arquivo acima disso é streaming")
    parser.add_argument("--rate", type=float, default=5.0, help="Máx. req/s por host")
    parser.add_argument("--proxy", help="Proxy HTTP")
    parser.add_argument("--oob-url", help="Sink out-of-band para achados cegos")
    parser.add_argument("--allow-private", action="store_true", help="Permite alvos privados/loopback (testes)")
    parser.add_argument("--verbose", action="store_true", help="Log detalhado")
    return parser


def _positive(parser: argparse.ArgumentParser, name: str, value: float) -> None:
    if value <= 0:
        parser.error(f"{name} deve ser > 0")


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    outputs = Path(args.outputs).expanduser().resolve()
    if not outputs.exists() or not outputs.is_dir():
        parser.print_usage(sys.stderr)
        print(f"triager: pasta de outputs inexistente: {outputs}", file=sys.stderr)
        return 2
    out_dir = Path(args.out).expanduser().resolve() if args.out else outputs / "_analysis"
    if out_dir == outputs:
        print("triager: --out não pode ser igual à pasta de outputs", file=sys.stderr)
        return 2
    for name, value in (
        ("--max-minutes", args.max_minutes),
        ("--max-requests", args.max_requests),
        ("--file-max-seconds", args.file_max_seconds),
        ("--file-max-mb", args.file_max_mb),
        ("--rate", args.rate),
        ("--max-candidates", args.max_candidates),
    ):
        _positive(parser, name, float(value))
    if args.per_target_max_minutes is not None:
        _positive(parser, "--per-target-max-minutes", args.per_target_max_minutes)

    try:
        scopes = load_targets(args.targets, args.targets_file, args.allow_private)
    except ScopeError as exc:
        print(f"triager: {exc}", file=sys.stderr)
        return 2
    has_targets = bool(scopes)
    scope_hosts = {scope.host for scope in scopes}
    recon_only = bool(args.recon_only or not has_targets)

    if args.resume and not (out_dir / "state.json").exists():
        print(f"triager: --resume sem estado em {out_dir / 'state.json'}", file=sys.stderr)
        return 3

    files, truncated = discover.list_files(outputs, out_dir)
    if not files:
        parser.print_usage(sys.stderr)
        print(f"triager: nenhum output encontrado em {outputs}", file=sys.stderr)
        return 2

    grouped, heuristic = discover.attribute_files(files, True if args.split_dir else None, scope_hosts)
    found_subs = sorted(grouped)
    primary_subs = [
        sub for sub in found_subs if sub != "unassigned" and (looks_like_sub(sub) or sub in scope_hosts)
    ]
    if not primary_subs:
        primary_subs = ["unassigned"] if "unassigned" in grouped else []
    ordered_subs: list[str] = []
    for scope in scopes:
        if scope.host in grouped:
            ordered_subs.append(scope.host)
    for sub in primary_subs:
        if sub not in ordered_subs:
            ordered_subs.append(sub)
    if not ordered_subs:
        ordered_subs = primary_subs

    inferred_host = None
    if not has_targets and primary_subs:
        inferred_host = max(primary_subs, key=lambda name: (len(grouped.get(name, [])), name != "unassigned"))

    n_subs = max(1, len(ordered_subs))
    if args.per_target_max_minutes:
        per_target_seconds = max(1.0, args.per_target_max_minutes * 60.0)
    else:
        per_target_seconds = max(60.0, float(int(args.max_minutes * 60 / n_subs)))
    effective_candidates = int(args.max_candidates)
    low_budget = per_target_seconds < 240
    if low_budget:
        effective_candidates = min(5, effective_candidates)
    max_total = args.max_total_requests if args.max_total_requests is not None else args.max_requests * n_subs
    budget = Budget(
        args.max_minutes,
        per_target_seconds,
        args.max_requests,
        max_total,
        budget_scope=args.budget_scope,
    )
    budget.rate = args.rate

    run_id = uuid.uuid4().hex[:12]
    state_path = out_dir / "state.json"
    existing_root = load_json(state_path, None)
    run_number = int((existing_root or {}).get("run_number", 0)) + 1
    budget_meta = {
        "max_minutes": args.max_minutes,
        "per_target_seconds": per_target_seconds,
        "max_requests": args.max_requests,
        "max_total_requests": max_total,
        "budget_scope": args.budget_scope,
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    if existing_root:
        root = existing_root
        root["run_id"] = run_id
        root["run_number"] = run_number
        root["outputs_dir"] = str(outputs)
        root["out_dir"] = str(out_dir)
        root["budget"] = budget_meta
        root.setdefault("targets", {})
        if not args.resume:
            for sub in ordered_subs:
                root["targets"].setdefault(sub, {})["status"] = "pending"
    else:
        root = new_root_state(run_id, run_number, str(outputs), str(out_dir), budget_meta)

    if args.proxy:
        os.environ["HTTP_PROXY"] = args.proxy
        os.environ["HTTPS_PROXY"] = args.proxy
        os.environ["http_proxy"] = args.proxy
        os.environ["https_proxy"] = args.proxy

    from triager.state import RunContext

    ctx = RunContext(outputs, out_dir, args, run_id, run_number, root, args.resume)
    ctx.budget = budget
    ctx.scopes = {scope.host: scope for scope in scopes}
    ctx.inferred_host = inferred_host

    def on_expire(reason: str) -> None:
        try:
            ctx.flush_all(reason)
            print(f"triager: encerrado pelo watchdog: {reason}", file=sys.stderr)
            print(f"triager: relatórios em {out_dir}", file=sys.stderr)
        finally:
            pass

    watchdog = Watchdog(budget, on_expire)
    ctx.watchdog = watchdog

    def on_signal(signum, frame):
        watchdog.stop()
        try:
            ctx.flush_all(f"sinal {signum} recebido")
            print(f"triager: sinal {signum}; estado e relatórios salvos.", file=sys.stderr)
        finally:
            os._exit(0)

    try:
        signal.signal(signal.SIGINT, on_signal)
        signal.signal(signal.SIGTERM, on_signal)
    except ValueError:
        pass

    watchdog.start()
    try:
        for sub in ordered_subs:
            sub_files = grouped.get(sub, [])
            authorized = sub in scope_hosts
            ctx.budget.start_target(sub)
            try:
                state = ctx.register(sub, authorized, heuristic)
            except Exception as exc:  # a bad folder name never aborts the run
                root["targets"].setdefault(sub, {})["status"] = "error"
                print(f"triager: subdomínio '{sub}' ignorado: {type(exc).__name__}: {exc}", file=sys.stderr)
                continue
            if args.resume and root.get("targets", {}).get(sub, {}).get("status") == "done":
                ctx.frozen.add(sub)
                ctx.flush(sub)
                continue
            state["status"] = "running"
            state["phases"]["prep"] = {
                "status": "done",
                "started_utc": utcnow(),
                "finished_utc": utcnow(),
            }
            if low_budget and state.get("run_number", run_number) == run_number:
                warning = (
                    f"Orçamento por subdomínio de {per_target_seconds:.0f}s (<240s): "
                    "lote reduzido e menos payloads/variações."
                )
                if warning not in state.get("notes", []):
                    state["notes"].append(warning)
            ctx.flush(sub)

            try:
                discover.run_inventory(ctx, sub, sub_files)

                phase = state["phases"]["triage"]
                phase["status"] = "running"
                phase["started_utc"] = phase.get("started_utc") or utcnow()
                ctx.budget.mark_phase("triage")
                ctx.budget.check_phase("triage")
                candidates = ctx.candidate_list(sub)
                triage.apply(candidates, scope_hosts, inferred_host, has_targets)
                selected = triage.select_batch(candidates, effective_candidates)
                state["selected_batch"] = selected
                state["checkpoint"] = {
                    "at_utc": utcnow(),
                    "requests_remaining": max(0, budget.max_requests - budget.requests_target),
                    "seconds_remaining": round(budget.target_remaining(), 2),
                    "batch_size": len(selected),
                    "all_in_scope": all(item.get("host") in scope_hosts for item in selected) if has_targets else None,
                    "stop_criteria": "≤10 req/candidata, 3-strikes, ≤5 payloads/vetor",
                    "low_budget": low_budget,
                }
                phase["status"] = "done"
                phase["finished_utc"] = utcnow()
                ctx.upsert_candidates(sub, candidates)
                report.write_sub_reports(ctx, sub)
                ctx.flush(sub)

                validate_phase = state["phases"]["validate"]
                if not has_targets:
                    validate_phase["status"] = "skipped"
                    validate_phase["reason"] = "alvo não informado — validação não executada"
                    for item in candidates:
                        if item.get("flag") == "active" and item.get("status") == "pending":
                            item["status"] = "Não testada (alvo não informado)"
                    state["status"] = "done"
                elif recon_only:
                    validate_phase["status"] = "skipped"
                    validate_phase["reason"] = "--recon-only"
                    for item in candidates:
                        if item.get("flag") == "active" and item.get("status") == "pending":
                            item["status"] = "Não testada (--recon-only)"
                    state["status"] = "done"
                elif not authorized:
                    validate_phase["status"] = "skipped"
                    validate_phase["reason"] = "subdomínio sem alvo autorizado em --targets"
                    state["status"] = "done"
                else:
                    scope = ctx.scopes[sub]
                    logger = ctx.logger(sub)

                    def out_of_scope(url: str, reason: str, _sub=sub) -> None:
                        ctx.add_out_of_scope(_sub, url, reason)

                    client = HttpClient(scope, budget, logger=logger, phase="validate", on_out_of_scope=out_of_scope)
                    run_validation(ctx, sub, client, selected)
                    state["status"] = "done" if state["phases"]["validate"].get("status") != "partial" else "partial"

                state["phases"]["report"]["status"] = "done"
                state["phases"]["report"]["started_utc"] = state["phases"]["report"].get("started_utc") or utcnow()
                state["phases"]["report"]["finished_utc"] = utcnow()
                if state.get("status") == "running":
                    state["status"] = "done"
                ctx.upsert_candidates(sub, candidates)
                report.write_sub_reports(ctx, sub)
                ctx.flush(sub)
                root["targets"].setdefault(sub, {})["status"] = state["status"]
                ctx.save_root()
            except BudgetExceeded as exc:
                state["status"] = "partial"
                state["partial_reason"] = str(exc)
                ctx.add_skip(sub, "budget", str(exc))
                ctx.flush(sub)
            except Exception as exc:  # one subdomain never aborts the run
                state["status"] = "aborted"
                state["partial_reason"] = f"{type(exc).__name__}: {exc}"
                ctx.logger(sub).exception("falha inesperada no subdomínio %s", sub)
                ctx.flush(sub)
            if budget.expired_reason():
                break
    finally:
        watchdog.stop()
        ctx.flush_all("finalização")
        try:
            ctx.save_root()
        except Exception:
            pass

    total_findings = sum(len(state.get("findings", [])) for state in ctx.subs.values())
    confirmed = sum(
        1
        for state in ctx.subs.values()
        for finding in state.get("findings", [])
        if finding.get("status") == "Confirmada"
    )
    print(
        f"triager: execução #{run_number} concluída · subdomínios={len(ctx.subs)} · "
        f"achados={total_findings} (confirmados={confirmed}) · requisições={budget.requests_total}"
    )
    if truncated:
        print("triager: aviso: inventário truncado em 5000 entradas", file=sys.stderr)
    if not has_targets:
        print("triager: alvo não informado — validação não executada (somente leitura)", file=sys.stderr)
    for sub, state in ctx.subs.items():
        folder = ctx.out / state.get("folder", safe_folder(sub))
        print(f"  {sub} [{state.get('status')}] {folder / 'RECON.md'}")
        print(f"  {sub} [{state.get('status')}] {folder / 'FINDINGS.md'}")
    print(f"  índice: {ctx.out / 'INDEX.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
