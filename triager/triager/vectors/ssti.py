"""Server-side template injection validator."""

from __future__ import annotations

NAME = "ssti"


def validate(vctx) -> dict:
    params = vctx.params(["name", "q", "template", "message", "search"])
    param = params[0]
    baseline = vctx.baseline().text or ""
    # limite: 4 payloads de SSTI.
    for payload, expected in (
        ("{{1337*1337}}", "1787569"),
        ("${1337*1337}", "1787569"),
        ("<%= 1337*1337 %>", "1787569"),
        ("#{1337*1337}", "1787569"),
    ):
        response = vctx.get(vctx.build_url(param, payload))
        if expected in (response.text or "") and expected not in baseline:
            return vctx.result(
                status="Confirmada",
                payload=payload,
                evidence=f"expressão avaliada para {expected}",
                impact="Avaliação server-side de template; pode escalar para execução de código.",
                severity="high",
                title="Server-side template injection",
            )
    return vctx.result(
        status="Não reproduzida",
        payload="{{1337*1337}}",
        evidence="expressão não avaliada na resposta",
        impact="",
        severity=vctx.item.get("severity_declared") or "high",
        title="SSTI não reproduzido",
    )
