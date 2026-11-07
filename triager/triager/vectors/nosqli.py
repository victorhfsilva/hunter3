"""NoSQL injection validator."""

from __future__ import annotations

NAME = "nosqli"


def validate(vctx) -> dict:
    params = vctx.params(["id", "user", "username"])
    param = params[0]
    control = vctx.get(vctx.item["endpoint"])
    response = vctx.get(vctx.build_url(f"{param}[$ne]", "x"))
    if response.status == 200 and vctx.body_changed(control.text, response.text):
        return vctx.result(
            status="Provável (parcial)",
            payload=f"{param}[$ne]=x",
            evidence=f"status={response.status}; corpo diferente do controle",
            impact="Possível bypass de filtro NoSQL; requer confirmar a query do backend.",
            severity="medium",
            title="Possível NoSQL injection",
            impact_demonstrated=False,
            counter_evidence="parâmetro pode ter sido ignorado",
        )
    return vctx.result(
        status="Não reproduzida",
        payload=f"{param}[$ne]=x",
        evidence="operador sem efeito observável",
        impact="",
        severity=vctx.item.get("severity_declared") or "medium",
        title="NoSQLi não reproduzido",
    )
