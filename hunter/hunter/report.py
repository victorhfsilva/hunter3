"""Incremental, atomic RECON/FINDINGS/INDEX rendering."""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from .state import atomic_write_text, utcnow


def mask_email(email: str) -> str:
    if "@" not in email:
        return "[mascarado]"
    local, domain = email.split("@", 1)
    first = local[:1] if local else "*"
    return f"{first}***@{domain}"


def truncate_secret(secret: str) -> str:
    secret = secret or ""
    if len(secret) <= 12:
        return secret[:4] + "***"
    return f"{secret[:8]}...{secret[-4:]}"


def _cell(value) -> str:
    return str(value if value is not None else "").replace("|", "\\|").replace("\n", " ")


def _status_line(state: dict) -> str:
    status = state.get("status", "pending")
    reason = state.get("partial_reason") or state.get("error")
    if status in ("partial", "aborted") and reason:
        return f"{status} ({reason})"
    return status


def _budget_line(ctx, state: dict) -> str:
    seconds = state.get("budget_used", {}).get("target_seconds") or 0
    minutes = seconds / 60.0 if seconds else 0
    max_requests = getattr(ctx.budget, "max_requests", "?") if ctx.budget else "?"
    return f"{minutes:.2f} min / {max_requests} req"


def _render_ai(state: dict) -> list[str]:
    ai_state = state.get("ai") or {}
    lines = ["", "## Plano de IA (opencode)"]
    if not ai_state.get("enabled"):
        reason = ai_state.get("reason") or "não disponível"
        lines.append(f"- IA desativada/indisponível: {_cell(reason)}")
        return lines
    lines.append(f"- Provider: `{ai_state.get('provider', '?')}` · motivo/credencial: {_cell(ai_state.get('reason', ''))}")
    rounds = ai_state.get("rounds") or []
    if rounds:
        lines.append("")
        lines.append("| Estágio | Rodada | Duração (s) | Propostas | Aceitas | Rejeitadas | Erro |")
        lines.append("|---|---|---|---|---|---|---|")
        for item in rounds[-12:]:
            lines.append(
                f"| {_cell(item.get('stage'))} | {item.get('round')} | {item.get('duration_seconds', 0)} "
                f"| {item.get('proposals', 0)} | {item.get('accepted', 0)} | {item.get('rejected', 0)} "
                f"| {_cell(item.get('error', ''))} |"
            )
    accepted = ai_state.get("accepted") or []
    if accepted:
        lines.append("")
        lines.append("Testes aceitos da IA (validados por allowlist de host/classe):")
        for item in accepted[:40]:
            lines.append(
                f"- `{_cell(item.get('method'))} {_cell(item.get('url'))}` · classes: {_cell(', '.join(item.get('classes', [])))} "
                f"· estágio: {_cell(item.get('stage'))} · motivo: {_cell(item.get('reason', ''))}"
            )
    rejected = ai_state.get("rejected") or []
    if rejected:
        lines.append("")
        lines.append(f"Propostas rejeitadas: {len(rejected)} (fora de escopo/classe/malformadas).")
        for item in rejected[-10:]:
            lines.append(f"- {_cell(item.get('reason'))}")
    notes = ai_state.get("notes") or []
    if notes:
        lines.append("")
        for note in notes[-15:]:
            lines.append(f"- {_cell(note)}")
    return lines


def render_recon(ctx, host: str) -> str:
    state = ctx.targets[host]
    recon = state.get("recon", {})
    lines = [
        f"# RECON — {host}",
        "",
        f"- Última atualização (UTC): {utcnow()} · Execução: {state.get('run_id', ctx.run_id)} · Orçamento: {_budget_line(ctx, state)}",
        f"- Status: {_status_line(state)}",
        f"- Nota de escopo: apenas {host}; terceiros apenas registrados",
        "",
        "## Target",
        f"- URL base: {state.get('base_url', '')}",
        f"- Host: `{host}` · Porta: {state.get('port')} · Esquema: {state.get('scheme')}",
        f"- Requisições consumidas: {state.get('counters', {}).get('requests_total', 0)}",
        f"- Requisições fora do escopo: {state.get('counters', {}).get('requests_out_of_scope', 0)}",
        f"- Perfil de profundidade: `{getattr(ctx, 'settings', None).profile if getattr(ctx, 'settings', None) else '?'}`",
        "",
        "## WAF/CDN (vendor, confiança, evidências)",
    ]
    waf = recon.get("waf", {}) or {}
    if waf.get("vendor"):
        lines.append(f"- Vendor: **{waf.get('vendor')}** · Confiança: {waf.get('confidence', 'baixa')}")
        for evidence in waf.get("evidence", [])[:8]:
            lines.append(f"  - `{_cell(evidence)}`")
    else:
        lines.append("- WAF/CDN: não detectado (nenhuma assinatura conhecida).")

    lines += _render_ai(state)

    lines += ["", "## GraphQL"]
    graphql = recon.get("graphql", {}) or {}
    if graphql.get("path"):
        lines.append(f"- Endpoint: `{graphql.get('path')}` · Status: {graphql.get('status')}")
        lines.append(f"- `__typename` respondeu: {graphql.get('typename_ok', False)}")
        lines.append(f"- Introspection: {graphql.get('introspection', 'não testada')}")
        if graphql.get("query_type"):
            lines.append(f"- queryType: `{graphql.get('query_type')}` · mutationType: `{graphql.get('mutation_type', '—')}`")
        if graphql.get("batching") is not None:
            lines.append(f"- Batching: {graphql.get('batching')}")
        if graphql.get("mutations_without_auth"):
            lines.append("- Mutations sem autenticação: sinalizado")
        for note in graphql.get("notes", [])[:8]:
            lines.append(f"- {note}")
    else:
        lines.append("- Nenhum endpoint GraphQL detectado.")

    lines += ["", "## API endpoints (método, status, parâmetros, origem: html|js|leakpath)", ""]
    endpoints = recon.get("api_endpoints", [])
    if endpoints:
        lines.append("| Método | URL | Status | Parâmetros | Origem |")
        lines.append("|---|---|---|---|---|")
        for item in endpoints[:120]:
            lines.append(
                f"| {_cell(item.get('method', 'GET'))} | `{_cell(item.get('url'))}` | {_cell(item.get('status', '—'))} "
                f"| {_cell(', '.join(item.get('params', [])))} | {_cell(item.get('source', ''))} |"
            )
    else:
        lines.append("- Nenhum endpoint de API colhido.")

    lines += ["", "## JS bundles analisados (URL, tamanho, endpoints extraídos)"]
    bundles = recon.get("js_bundles", [])
    if bundles:
        for bundle in bundles[:22]:
            lines.append(
                f"- `{bundle.get('url')}` · {bundle.get('size', 0)} bytes · "
                f"{len(bundle.get('endpoints', []))} endpoint(s) · source map: {bundle.get('sourcemap', 'não')}"
            )
            for endpoint in bundle.get("endpoints", [])[:20]:
                lines.append(f"  - `{_cell(endpoint)}`")
    else:
        lines.append("- Nenhum bundle JS analisado.")

    lines += ["", "## Caminhos de vazamento (path, status, achado)"]
    leaks = recon.get("leak_paths", [])
    if leaks:
        lines.append("| Path | Status | Achado |")
        lines.append("|---|---|---|")
        for leak in leaks:
            lines.append(f"| `{_cell(leak.get('path'))}` | {leak.get('status')} | {_cell(leak.get('note', ''))} |")
    else:
        lines.append("- Nenhum caminho de vazamento testado ou todos 404.")

    lines += ["", "## Formulários descobertos"]
    forms = recon.get("forms", [])
    if forms:
        lines.append("| Ação | Método | Parâmetros |")
        lines.append("|---|---|---|")
        for form in forms[:60]:
            lines.append(f"| `{_cell(form.get('url'))}` | {_cell(form.get('method'))} | {_cell(', '.join(form.get('params', [])))} |")
    else:
        lines.append("- Nenhum formulário extraído.")

    openapi = recon.get("openapi", {}) or {}
    lines += ["", "## OpenAPI/Swagger"]
    if openapi.get("endpoints"):
        lines.append(f"- Documento: `{_cell(openapi.get('url'))}` · versão: {_cell(openapi.get('version', ''))} · paths: {openapi.get('path_count', 0)}")
        for endpoint in openapi.get("endpoints", [])[:60]:
            lines.append(f"  - `{_cell(endpoint.get('method'))} {_cell(endpoint.get('url'))}` · params: {_cell(', '.join(endpoint.get('params', [])))}")
    else:
        lines.append("- Nenhum schema OpenAPI acessível.")

    lines += ["", "## robots.txt / sitemap.xml"]
    robots = recon.get("robots", {}) or {}
    sitemap = recon.get("sitemap", {}) or {}
    if robots.get("status") is not None:
        lines.append(f"- robots.txt: status {robots.get('status')} · {len(robots.get('paths', []))} path(s) · {len(robots.get('sitemaps', []))} sitemap(s)")
        for path in robots.get("paths", [])[:40]:
            lines.append(f"  - `{_cell(path)}`")
    if sitemap.get("count"):
        lines.append(f"- sitemap: {sitemap.get('count')} URL(s)")
    if not robots.get("status") and not sitemap.get("count"):
        lines.append("- Nenhum robots/sitemap coletado.")

    lines += ["", "## Parâmetros minerados"]
    params = recon.get("params", [])
    lines.append(f"- {', '.join(f'`{_cell(name)}`' for name in params[:80])}" if params else "- Nenhum parâmetro minerado.")

    lines += ["", "## Fingerprint de tech"]
    tech = recon.get("tech", {}) or {}
    if tech:
        for key, value in tech.items():
            lines.append(f"- {key}: `{_cell(value)}`")
    else:
        lines.append("- Não determinado.")

    lines += ["", "## Segredos (truncados, tipo, origem)"]
    secrets = recon.get("secrets", [])
    if secrets:
        for secret in secrets:
            lines.append(
                f"- `{truncate_secret(secret.get('value', ''))}` · tipo: {secret.get('type', '?')} · origem: `{secret.get('source', '')}`"
            )
    else:
        lines.append("- Nenhum segredo aparente encontrado.")

    lines += ["", "## Superfícies de login/registro"]
    surfaces = recon.get("login_surfaces", [])
    if surfaces:
        for surface in surfaces:
            lines.append(f"- {surface.get('kind', 'surface')}: `{surface.get('url')}` (status {surface.get('status', '—')})")
    else:
        lines.append("- Nenhuma superfície de login/registro identificada.")

    lines += ["", "## Contas de teste (e-mails mascarados) — ou \"não fornecidas\""]
    accounts = recon.get("accounts", [])
    if accounts:
        for account in accounts:
            lines.append(f"- {mask_email(account.get('email', ''))} · status: {account.get('status', '?')} · {account.get('note', '')}")
    else:
        lines.append("- Não fornecidas (sem contas de teste fornecidas).")

    lines += ["", "## Notas para teste manual (rabbit holes encerrados)"]
    notes = recon.get("notes", [])
    if notes:
        for note in notes[:60]:
            lines.append(f"- {note}")
    else:
        lines.append("- Nenhuma nota.")

    lines += ["", "## Subetapas puladas (subetapa, motivo: timeout|orçamento|limite de requisições|bloqueio)"]
    skipped = state.get("skipped", [])
    if skipped:
        for item in skipped[:50]:
            lines.append(f"- {_cell(item.get('substep'))}: {_cell(item.get('reason'))}")
    else:
        lines.append("- Nenhuma.")

    lines += ["", "## Fora de escopo registrado (URL, motivo, NÃO testado)"]
    out = state.get("out_of_scope", [])
    if out:
        for item in out[:80]:
            lines.append(f"- `{_cell(item.get('url'))}` · {_cell(item.get('reason'))} · testado: não")
    else:
        lines.append("- Nenhum.")

    lines += ["", "## Incidentes de escopo (se alguma requisição saiu do host do alvo)"]
    incidents = state.get("incidents", [])
    if incidents:
        for incident in incidents:
            lines.append(f"- {_cell(incident.get('detail'))} ({incident.get('at_utc')})")
    else:
        lines.append("- Nenhum. Zero requisições fora do host do alvo.")
    lines.append("")
    return "\n".join(lines)


def render_findings(ctx, host: str) -> str:
    state = ctx.targets[host]
    findings = state.get("findings", [])
    counts = Counter((finding.get("severity", "low"), finding.get("status", "potential")) for finding in findings)
    total_by_status = Counter(finding.get("status", "potential") for finding in findings)
    lines = [
        f"# FINDINGS — {host}",
        "",
        f"- Última atualização (UTC): {utcnow()} · Execução: {state.get('run_id', ctx.run_id)}",
        f"- Status: {_status_line(state)}",
        f"- Total: {len(findings)} · likely: {total_by_status.get('likely', 0)} · "
        f"potential: {total_by_status.get('potential', 0)}",
        "",
        "## Resumo (contagem por severidade/status)",
        "| # | Vuln class | Title | Severity | Status |",
        "|---|---|---|---|---|",
    ]
    for finding in findings:
        lines.append(
            f"| {_cell(finding.get('id'))} | {_cell(finding.get('class'))} | {_cell(finding.get('title'))} "
            f"| {_cell(finding.get('severity'))} | {_cell(finding.get('status'))} |"
        )
    if findings:
        lines.append("")
        lines.append(
            "Severidade/status: "
            + ", ".join(f"{sev}/{status}={count}" for (sev, status), count in sorted(counts.items()))
        )
    lines += ["", "## Detalhes"]
    if not findings:
        lines.append("_No findings were produced._")
    for finding in findings:
        lines += [
            "",
            f"### {finding.get('id')} — {finding.get('title')}",
            f"- Classe / Severidade / Status: {finding.get('class')} / {finding.get('severity')} / {finding.get('status')}",
            f"- `{finding.get('method', 'GET')} {finding.get('endpoint', '')}`",
            f"- Payload: `{_cell(finding.get('payload', ''))}`",
            f"- Evidência: {finding.get('evidence', '—')}",
            f"- Impacto: {finding.get('impact', '—')}",
            f"- Prerequisitos: {finding.get('prerequisites', '—')}",
            f"- Contraevidência testada: {finding.get('counter_evidence', '—')}",
            f"- O que mudaria a severidade: {finding.get('severity_change', '—')}",
            f"- Gate 7 perguntas: {'passou' if finding.get('gate_passed', True) else 'falhou — ' + ', '.join(finding.get('gate_failed', []))}",
            f"- Origem: {_cell(finding.get('origin') or finding.get('tool_origin') or 'scanner')}"
            + (f" · IA ({_cell(finding.get('ai_stage'))}): {_cell(finding.get('ai_reason'))}" if finding.get("ai_stage") else ""),
            f"- Timestamp UTC: {finding.get('found_utc', '')} · última verificação: {finding.get('updated_utc', '')}",
        ]

    lines += ["", "## Cobertura testada (endpoint × classe × resultado)", ""]
    coverage = state.get("coverage", [])
    if coverage:
        lines.append("| Endpoint | Classe | Resultado | Detalhe |")
        lines.append("|---|---|---|---|")
        for item in coverage[-200:]:
            lines.append(
                f"| `{_cell(item.get('endpoint'))}` | {_cell(item.get('class'))} "
                f"| {_cell(item.get('result'))} | {_cell(item.get('detail', ''))} |"
            )
    else:
        lines.append("- Nenhuma cobertura registrada.")

    lines += ["", "## Não testado / bloqueado (motivo)"]
    blocked = [item for item in state.get("skipped", []) if "endpoint" in str(item.get("substep", ""))]
    if blocked:
        for item in blocked[:60]:
            lines.append(f"- {_cell(item.get('substep'))}: {_cell(item.get('reason'))}")
    else:
        lines.append("- Nenhum endpoint bloqueado registrado.")
    lines.append("")
    return "\n".join(lines)


def write_target_reports(ctx, host: str) -> None:
    tdir = ctx.target_dir(host)
    tdir.mkdir(parents=True, exist_ok=True)
    atomic_write_text(tdir / "RECON.md", render_recon(ctx, host))
    atomic_write_text(tdir / "FINDINGS.md", render_findings(ctx, host))


def write_index(ctx) -> None:
    lines = [
        "# HUNTER INDEX",
        "",
        f"- Última atualização (UTC): {utcnow()} · Execução: {ctx.run_id}",
        f"- Alvos: {len(ctx.targets)} · Requisições totais: {getattr(ctx.budget, 'requests_total', 0) if ctx.budget else 0}",
        "",
        f"- Perfil: `{getattr(ctx, 'settings', None).profile if getattr(ctx, 'settings', None) else '?'}` · IA: "
        + ("habilitada" if any((state.get('ai') or {}).get('enabled') for state in ctx.targets.values()) else "desativada"),
        "",
        "| Subdomínio | Status | Requisições | Achados | Rodadas IA | RECON | FINDINGS |",
        "|---|---|---|---|---|---|---|",
    ]
    for host, state in ctx.targets.items():
        folder = state.get("folder", host)
        lines.append(
            f"| `{host}` | {_status_line(state)} | {state.get('counters', {}).get('requests_total', 0)} "
            f"| {len(state.get('findings', []))} | {len((state.get('ai') or {}).get('rounds', []))} "
            f"| [{folder}/RECON.md]({folder}/RECON.md) | [{folder}/FINDINGS.md]({folder}/FINDINGS.md) |"
        )
    lines += ["", "## Achados consolidados", ""]
    rows = [(host, finding) for host, state in ctx.targets.items() for finding in state.get("findings", [])]
    if rows:
        lines += ["| Subdomínio | # | Classe | Título | Severidade | Status |", "|---|---|---|---|---|---|"]
        for host, finding in rows:
            lines.append(
                f"| `{host}` | {_cell(finding.get('id'))} | {_cell(finding.get('class'))} | {_cell(finding.get('title'))} "
                f"| {_cell(finding.get('severity'))} | {_cell(finding.get('status'))} |"
            )
    else:
        lines.append("_No findings were produced._")
    lines.append("")
    atomic_write_text(Path(ctx.out) / "INDEX.md", "\n".join(lines))
