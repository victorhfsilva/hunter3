"""Incremental atomic RECON/FINDINGS/INDEX rendering."""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from .state import atomic_write_text, utcnow

STATUSES = ["Confirmada", "Provável (parcial)", "Não reproduzida", "Falso-positivo", "Bloqueada", "Fora de escopo"]

CWE_MAP = {
    "xss": "CWE-79",
    "sqli": "CWE-89",
    "nosqli": "CWE-943",
    "ssrf": "CWE-918",
    "lfi": "CWE-22",
    "rfi": "CWE-98",
    "rce": "CWE-78",
    "open_redirect": "CWE-601",
    "idor": "CWE-639",
    "cors": "CWE-942",
    "csrf": "CWE-352",
    "ssti": "CWE-1336",
    "xxe": "CWE-611",
    "graphql": "CWE-200",
    "secret": "CWE-798",
    "misconfig": "CWE-16",
    "headers": "CWE-693",
    "tech": "CWE-1104",
}
FIX_MAP = {
    "xss": "codificar a saída por contexto e usar allowlist de entrada.",
    "sqli": "usar consultas parametrizadas e nunca concatenar entrada em SQL.",
    "nosqli": "validar tipos/allowlist e rejeitar operadores em entrada do usuário.",
    "ssrf": "allowlist de destinos, bloquear IPs privados e resolver DNS de forma segura.",
    "lfi": "resolver caminhos contra uma raiz fixa e negar traversal.",
    "rfi": "não incluir arquivos remotos; allowlist de templates locais.",
    "rce": "evitar shell, usar APIs parametrizadas e allowlist de comandos.",
    "open_redirect": "aceitar apenas destinos relativos ou allowlist de hosts.",
    "idor": "checar autorização por objeto em cada requisição.",
    "cors": "não refletir Origin arbitrário; allowlist explícita e sem credenciais.",
    "csrf": "token anti-CSRF, SameSite e verificação de Origin.",
    "ssti": "não renderizar entrada em templates; usar variáveis escapadas.",
    "xxe": "desabilitar entidades externas e DTD no parser XML.",
    "graphql": "desabilitar introspection em produção e limitar profundidade/batching.",
    "secret": "revogar/rotacionar o segredo e removê-lo do repositório.",
    "misconfig": "revisar configuração e exposição de debug/arquivos.",
    "headers": "adicionar headers de segurança (HSTS, CSP, X-Content-Type-Options).",
    "tech": "atualizar o componente e confirmar a versão corrigida.",
}


def _cell(value) -> str:
    return str(value if value is not None else "").replace("|", "\\|").replace("\n", " ")


def _status_line(state: dict) -> str:
    status = state.get("status", "pending")
    reason = state.get("partial_reason")
    return f"{status} ({reason})" if status in ("partial", "aborted") and reason else status


def _budget_line(ctx, state: dict) -> str:
    seconds = state.get("budget_used", {}).get("target_seconds") or 0
    minutes = seconds / 60.0 if seconds else 0
    max_requests = getattr(ctx.budget, "max_requests", "?") if ctx.budget else "?"
    return f"{minutes:.2f} min / {max_requests} req"


def _validation_enabled(ctx) -> bool:
    return bool(ctx.scopes) and not getattr(ctx.args, "recon_only", False)


def render_recon(ctx, sub: str) -> str:
    state = ctx.subs[sub]
    files = state.get("files", {})
    candidates = state.get("candidates", [])
    lines = [
        f"# RECON — {sub}",
        "",
        f"- Última atualização (UTC): {utcnow()} · Execução #{state.get('run_number')} · Orçamento: {_budget_line(ctx, state)}",
        f"- Status: {_status_line(state)}",
        f"- Alvo autorizado (de --targets): {sub if state.get('authorized') else 'não informado — validação desativada'}",
        f"- Heurística de atribuição do subdomínio: {state.get('inference', 'inferida')}",
        "",
        "## Inventário de arquivos",
        "",
        "| # | Arquivo | Tool detectada | Tamanho | Status | Candidatas | Offset | Motivo |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for index, (rel, entry) in enumerate(sorted(files.items()), start=1):
        lines.append(
            f"| {index} | `{_cell(rel)}` | {_cell(entry.get('tool'))} | {entry.get('size', 0)} "
            f"| {_cell(entry.get('status'))} | {entry.get('candidates', 0)} | {entry.get('offset', 0)} | {_cell(entry.get('reason', ''))} |"
        )
    if not files:
        lines.append("| - | - | - | - | - | - | - | - |")

    tool_counts: dict[str, Counter] = {}
    for entry in files.values():
        bucket = tool_counts.setdefault(entry.get("tool", "?"), Counter())
        bucket[entry.get("status", "?")] += 1
    lines += ["", "## Cobertura por tool (lidos / pulados / sem cobertura)", ""]
    if tool_counts:
        lines.append("| Tool | done | partial | skipped | error |")
        lines.append("|---|---|---|---|---|")
        for tool, counter in sorted(tool_counts.items()):
            lines.append(
                f"| {_cell(tool)} | {counter.get('done', 0)} | {counter.get('partial', 0)} "
                f"| {counter.get('skipped', 0)} | {counter.get('error', 0)} |"
            )
    else:
        lines.append("- Nenhum arquivo encontrado.")

    lines += [
        "",
        "## Candidatas extraídas",
        "",
        "| ID | Tipo | Endpoint | Param | Tool | Sev. declarada | Flag | Score |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for item in candidates[:300]:
        lines.append(
            f"| {item.get('id')} | {_cell(item.get('type'))} | `{_cell(item.get('endpoint'))}` | {_cell(item.get('param'))} "
            f"| {_cell(item.get('tool_origin'))} | {_cell(item.get('severity_declared'))} | {_cell(item.get('flag'))} | {item.get('score', 0)} |"
        )
    if not candidates:
        lines.append("| - | - | - | - | - | - | - | - |")
    elif len(candidates) > 300:
        lines.append(f"\n_Exibindo 300 de {len(candidates)} candidatas; lista completa em workspace/state.json._")

    lines += ["", "## Triagem", "", "### Fora de escopo (não testado)"]
    outside = [item for item in candidates if item.get("flag") == "out_of_scope"]
    if outside:
        for item in outside[:100]:
            lines.append(f"- `{_cell(item.get('endpoint'))}` · {_cell(item.get('triage_reason', ''))} · tool={item.get('tool_origin')}")
    else:
        lines.append("- Nenhuma.")
    lines += ["", "### Sem teste ativo (segredos — truncados, arquivo:linha)"]
    secrets = [item for item in candidates if item.get("type") == "secret"]
    if secrets:
        for item in secrets[:100]:
            lines.append(f"- {_cell(item.get('title'))} · `{_cell(item.get('evidence'))}` · severidade={item.get('severity_declared')}")
    else:
        lines.append("- Nenhum segredo registrado.")
    lines += ["", "### Baixa prioridade"]
    low = [item for item in candidates if item.get("flag") == "low_priority"]
    if low:
        for item in low[:100]:
            lines.append(f"- `{_cell(item.get('endpoint'))}` · {item.get('type')} · {_cell(item.get('triage_reason', ''))}")
    else:
        lines.append("- Nenhuma.")

    lines += ["", "## Correlações entre fontes"]
    correlated = [item for item in candidates if item.get("correlated_with")]
    if correlated:
        for item in correlated[:100]:
            lines.append(f"- {item.get('id')} ({item.get('type')}) correlaciona com {', '.join(item.get('correlated_with', [])[:10])}")
    else:
        lines.append("- Nenhuma correlação relevante.")

    lines += ["", "## Lote selecionado para validação (top N) e critério de parada"]
    batch = state.get("selected_batch", [])
    if not _validation_enabled(ctx):
        lines.append("- Validação não executada (sem --targets ou --recon-only).")
    elif batch:
        for item in batch:
            lines.append(
                f"- {item.get('id')} · {item.get('type')} · score={item.get('score')} · "
                f"critério: ≤10 req/candidata, 3-strikes, ≤5 payloads/vetor"
            )
    else:
        lines.append("- Nenhuma candidata ativa selecionada.")

    lines += ["", "## Oportunidades não planejadas (rabbit holes encerrados)"]
    notes = [note for note in state.get("notes", []) if "oportunidade" in note.lower()]
    if notes:
        for note in notes[-20:]:
            lines.append(f"- {_cell(note)}")
    else:
        lines.append("- Nenhuma.")

    lines += ["", "## Não coberto / limites atingidos (arquivo, motivo, candidatas pendentes)"]
    pending = [item for item in candidates if item.get("flag") == "active" and item.get("status") not in ("Confirmada", "Provável (parcial)", "Não reproduzida", "Falso-positivo", "Bloqueada")]
    skipped = state.get("skipped", [])
    if skipped or pending or any(entry.get("status") in ("partial", "skipped", "error") for entry in files.values()):
        for item in skipped[-30:]:
            lines.append(f"- limite: {_cell(item.get('unit'))} — {_cell(item.get('reason'))}")
        for entry in files.values():
            if entry.get("status") in ("partial", "skipped", "error"):
                lines.append(f"- arquivo `{_cell(entry.get('rel'))}`: {entry.get('status')} ({_cell(entry.get('reason', ''))})")
        if pending:
            lines.append(f"- candidatas pendentes para --resume: {len(pending)}")
    else:
        lines.append("- Nenhum limite atingido.")

    lines += ["", "## Incidentes de escopo (requisições fora do host do alvo — deve ser sempre vazio)"]
    incidents = state.get("incidents", [])
    if incidents:
        for incident in incidents:
            lines.append(f"- {_cell(incident.get('detail'))} ({incident.get('at_utc')})")
    else:
        lines.append("- Nenhum. Zero requisições fora do host do alvo.")
    lines.append("")
    return "\n".join(lines)


def render_findings(ctx, sub: str) -> str:
    state = ctx.subs[sub]
    findings = state.get("findings", [])
    counts = Counter((finding.get("severity", "low"), finding.get("status", "Não reproduzida")) for finding in findings)
    lines = [
        f"# FINDINGS — {sub}",
        "",
        f"- Última atualização (UTC): {utcnow()} · Execução #{state.get('run_number')}",
        f"- Status: {_status_line(state)}",
        "",
        "## Resumo (contagem por severidade × status)",
        "",
        "| # | Classe | Título | Endpoint | Severidade | Status | Tool de origem |",
        "|---|---|---|---|---|---|---|",
    ]
    for finding in findings:
        lines.append(
            f"| {finding.get('id')} | {_cell(finding.get('class'))} | {_cell(finding.get('title'))} "
            f"| `{_cell(finding.get('endpoint'))}` | {_cell(finding.get('severity'))} | {_cell(finding.get('status'))} "
            f"| {_cell(finding.get('tool_origin'))} |"
        )
    if findings:
        lines.append("")
        lines.append("Contagem: " + ", ".join(f"{sev}/{status}={count}" for (sev, status), count in sorted(counts.items())))
    else:
        lines.append("| - | - | - | - | - | - | - |")

    lines += ["", "## Detalhes"]
    if not findings:
        lines.append("_No findings were produced._")
    for finding in findings:
        lines += [
            "",
            f"### {finding.get('id')} — {finding.get('title')}",
            f"- Classe / Severidade / Status: {finding.get('class')} / {finding.get('severity')} / {finding.get('status')}",
            f"- `{finding.get('method', 'GET')} {finding.get('endpoint')}` · parâmetro: {finding.get('param') or '—'}",
            f"- Payload: `{_cell(finding.get('payload', ''))}`",
            f"- Evidência: {_cell(finding.get('evidence', ''))}",
            f"- Impacto demonstrado: {_cell(finding.get('impact', '')) or '—'}",
            f"- Prerequisitos: {_cell(finding.get('prerequisites') or '—')}",
            f"- Contraevidência testada: {_cell(finding.get('counter_evidence') or '—')}",
            f"- O que mudaria a severidade: {_cell(finding.get('severity_change') or '—')}",
            f"- Correção recomendada: {FIX_MAP.get(finding.get('class'), 'validar entrada, aplicar allowlist e revisar autorização no endpoint.')}",
            f"- Referência: {CWE_MAP.get(finding.get('class'), 'CWE relacionada à classe')}; VRT do programa quando disponível.",
            f"- Timestamp UTC: {finding.get('found_utc', '')} · última verificação: {finding.get('updated_utc', '')} · req gastas: {finding.get('requests', 0)}",
        ]

    lines += ["", "## Falsos-positivos e não reproduzidas (por quê)"]
    fakes = [item for item in findings if item.get("status") in ("Não reproduzida", "Falso-positivo")]
    if fakes:
        for item in fakes:
            lines.append(f"- {item.get('id')} · {item.get('class')} · `{_cell(item.get('endpoint'))}` — {_cell(item.get('evidence'))}")
    else:
        lines.append("- Nenhuma.")

    lines += ["", "## Cobertura de validação (candidata × vetor × req gastas × resultado)", ""]
    validated = [item for item in state.get("candidates", []) if item.get("validation")]
    if validated:
        lines.append("| Candidata | Classe | Endpoint | Req gastas | Resultado |")
        lines.append("|---|---|---|---|---|")
        for item in validated[:200]:
            validation = item.get("validation", {})
            lines.append(
                f"| {item.get('id')} | {_cell(item.get('type'))} | `{_cell(item.get('endpoint'))}` "
                f"| {validation.get('requests', 0)} | {_cell(validation.get('status', ''))} |"
            )
    else:
        lines.append("- Nenhuma validação executada.")

    lines += ["", "## Pendentes para --resume"]
    pending = [item for item in state.get("candidates", []) if item.get("flag") == "active" and item.get("status") in ("pending", "Bloqueada")]
    if pending:
        for item in pending[:100]:
            lines.append(f"- {item.get('id')} · {item.get('type')} · `{_cell(item.get('endpoint'))}` · status={item.get('status')}")
    else:
        lines.append("- Nenhuma.")
    lines.append("")
    return "\n".join(lines)


def write_sub_reports(ctx, sub: str) -> None:
    directory = ctx.sub_dir(sub)
    directory.mkdir(parents=True, exist_ok=True)
    atomic_write_text(directory / "RECON.md", render_recon(ctx, sub))
    atomic_write_text(directory / "FINDINGS.md", render_findings(ctx, sub))


def write_index(ctx) -> None:
    lines = [
        "# TRIAGER INDEX",
        "",
        f"- Última atualização (UTC): {utcnow()} · Execução #{ctx.run_number} · run_id={ctx.run_id}",
        f"- Outputs: `{ctx.outputs}`",
        f"- Orçamento: {ctx.root.get('budget', {}).get('max_minutes', '?')} min · "
        f"req/alvo={ctx.root.get('budget', {}).get('max_requests', '?')} ({ctx.root.get('budget', {}).get('budget_scope', '')}) · "
        f"req usadas={getattr(ctx.budget, 'requests_total', 0) if ctx.budget else 0}",
        "",
        "## Resumo executivo por subdomínio",
        "",
        "| Subdomínio | Status | Arquivos | Candidatas | confirmed | Provável | Não reproduzida | Fora de escopo | Req |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for sub, state in ctx.subs.items():
        findings = state.get("findings", [])
        by_status = Counter(item.get("status") for item in findings)
        lines.append(
            f"| `{sub}` | {_status_line(state)} | {len(state.get('files', {}))} | {len(state.get('candidates', []))} "
            f"| {by_status.get('Confirmada', 0)} | {by_status.get('Provável (parcial)', 0)} "
            f"| {by_status.get('Não reproduzida', 0)} "
            f"| {sum(1 for item in state.get('candidates', []) if item.get('flag') == 'out_of_scope')} "
            f"| {state.get('counters', {}).get('requests_total', 0)} |"
        )

    lines += ["", "## Achados confirmados / prováveis", ""]
    rows = [
        (sub, finding)
        for sub, state in ctx.subs.items()
        for finding in state.get("findings", [])
        if finding.get("status") in ("Confirmada", "Provável (parcial)")
    ]
    if rows:
        lines.append("| Subdomínio | # | Classe | Endpoint | Severidade | Status |")
        lines.append("|---|---|---|---|---|---|")
        for sub, finding in rows[:300]:
            lines.append(
                f"| `{sub}` | {finding.get('id')} | {_cell(finding.get('class'))} | `{_cell(finding.get('endpoint'))}` "
                f"| {_cell(finding.get('severity'))} | {_cell(finding.get('status'))} |"
            )
    else:
        lines.append("_No findings were produced._")

    lines += ["", "## Cobertura e limitações", ""]
    for sub, state in ctx.subs.items():
        failed = [entry for entry in state.get("files", {}).values() if entry.get("status") in ("partial", "skipped", "error")]
        pending = [item for item in state.get("candidates", []) if item.get("flag") == "active" and item.get("status") in ("pending", "Bloqueada")]
        lines.append(
            f"- `{sub}`: {len(failed)} arquivo(s) não totalmente lidos; {len(pending)} candidata(s) pendente(s)/bloqueada(s); "
            f"{len(state.get('out_of_scope', []))} item(ns) fora de escopo; {len(state.get('skipped', []))} limite(s) registrado(s)."
        )

    lines += ["", "## Fora de escopo e segredos (registrados sem teste ativo)", ""]
    any_rows = False
    for sub, state in ctx.subs.items():
        for item in state.get("candidates", []):
            if item.get("flag") == "out_of_scope":
                lines.append(f"- `{sub}` · fora de escopo: `{_cell(item.get('endpoint'))}` — {_cell(item.get('triage_reason', ''))}")
                any_rows = True
            elif item.get("type") == "secret":
                lines.append(f"- `{sub}` · segredo (truncado): {_cell(item.get('title'))} — `{_cell(item.get('evidence'))}`")
                any_rows = True
    if not any_rows:
        lines.append("- Nenhum.")

    lines += ["", "## Auditoria de conformidade", ""]
    for sub, state in ctx.subs.items():
        per_candidate = state.get("counters", {}).get("requests_by_candidate", {})
        max_req = max(per_candidate.values()) if per_candidate else 0
        out_scope = state.get("counters", {}).get("requests_out_of_scope", 0)
        lines.append(
            f"- `{sub}`: máximo de req em uma candidata = {max_req} (limite 10); "
            f"follow-ups de follow-up = 0; requisições fora do alvo = {out_scope}; "
            f"incidentes = {len(state.get('incidents', []))}."
        )
    lines += ["", "## Próximos passos", "", "- Reexecutar com `--resume` para validar candidatas pendentes.", ""]
    atomic_write_text(Path(ctx.out) / "INDEX.md", "\n".join(lines))
