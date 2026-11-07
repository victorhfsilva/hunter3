"""Reflected XSS validator."""

from __future__ import annotations

NAME = "xss"


def validate(vctx) -> dict:
    params = vctx.params(["q", "search", "name", "query"])
    baseline = vctx.baseline()
    baseline_text = baseline.text if baseline else ""
    for param in params[:2]:
        # limite: 3 payloads de XSS por parâmetro.
        for template in ("<{m}>", '"><{m}>', "'><{m}>"):
            marker = vctx.marker()
            payload = template.format(m=marker)
            response = vctx.get(vctx.build_url(param, payload))
            if marker in (response.text or "") and marker not in baseline_text:
                snippet = vctx.snippet(response.text, marker)
                return vctx.result(
                    status="Confirmada",
                    payload=payload,
                    evidence=f"marcador {marker} refletido cru em {param}; trecho: {snippet}",
                    impact="Script refletido é executado no contexto do navegador da vítima quando a resposta é HTML.",
                    severity="high",
                    title="XSS refletido",
                    counter_evidence="marcador ausente no baseline; execução em navegador real não testada",
                )
    return vctx.result(
        status="Não reproduzida",
        payload="",
        evidence="nenhum marcador refletido cru nas respostas testadas",
        impact="",
        severity=vctx.item.get("severity_declared") or "medium",
        title="XSS não reproduzido",
    )
