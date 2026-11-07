"""CORS validator."""

from __future__ import annotations

NAME = "cors"


def validate(vctx) -> dict:
    origin = "https://evil.invalid"
    response = vctx.get(vctx.item["endpoint"], headers={"Origin": origin})
    allow_origin = response.headers.get("access-control-allow-origin", "")
    allow_creds = response.headers.get("access-control-allow-credentials", "").lower()
    if allow_origin == origin and allow_creds == "true":
        return vctx.result(
            status="Confirmada",
            payload=f"Origin: {origin}",
            evidence=f"ACAO={allow_origin}; ACAC={allow_creds}; status={response.status}",
            impact="Um site externo pode ler respostas autenticadas deste endpoint no navegador da vítima.",
            severity="medium",
            title="CORS reflete origem arbitrária com credenciais",
        )
    if allow_origin == "*":
        return vctx.result(
            status="Provável (parcial)",
            payload=f"Origin: {origin}",
            evidence=f"ACAO=*; ACAC={allow_creds or '(ausente)'}; status={response.status}",
            impact="Leitura cross-origin de conteúdo possivelmente público; sem credenciais o impacto é limitado.",
            severity="low",
            title="CORS wildcard",
        )
    return vctx.result(
        status="Não reproduzida",
        payload=f"Origin: {origin}",
        evidence=f"ACAO={allow_origin or '(ausente)'}; ACAC={allow_creds or '(ausente)'}",
        impact="",
        severity=vctx.item.get("severity_declared") or "medium",
        title="CORS não reproduzido",
    )
