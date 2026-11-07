"""Command injection validator (echo canary only, non-destructive)."""

from __future__ import annotations

NAME = "rce"


def validate(vctx) -> dict:
    params = vctx.params(["cmd", "exec", "command", "ping", "host", "q"])
    param = params[0]
    marker = vctx.marker().upper()
    # limite: 3 payloads de RCE (somente echo canário).
    for payload in (f";echo {marker}", f"|echo {marker}", f"`echo {marker}`"):
        response = vctx.get(vctx.build_url(param, payload))
        if marker in (response.text or ""):
            return vctx.result(
                status="Confirmada",
                payload=payload,
                evidence=f"canário {marker} retornado pela resposta",
                impact="Execução de comandos no servidor (canário echo, sem efeitos destrutivos).",
                severity="critical",
                title="Command injection",
            )
    return vctx.result(
        status="Não reproduzida",
        payload=f";echo {marker}",
        evidence="canário não retornado",
        impact="",
        severity=vctx.item.get("severity_declared") or "critical",
        title="RCE não reproduzido",
    )
