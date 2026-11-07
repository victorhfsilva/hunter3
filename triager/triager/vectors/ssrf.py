"""SSRF validator. Blind SSRF is never confirmed without an OOB callback."""

from __future__ import annotations

NAME = "ssrf"


def validate(vctx) -> dict:
    params = vctx.params(["url", "uri", "image", "webhook", "proxy", "site", "host", "target"])
    if not params:
        return vctx.result(
            status="Não reproduzida",
            payload="",
            evidence="candidata sem parâmetro de URL",
            impact="",
            severity=vctx.item.get("severity_declared") or "high",
            title="SSRF não aplicável",
        )
    control = vctx.get(vctx.item["endpoint"])
    token = vctx.marker()
    if vctx.oob_url:
        probe = vctx.oob_url.replace("{token}", token) if "{token}" in vctx.oob_url else f"{vctx.oob_url.rstrip('/')}/{token}"
    else:
        probe = "http://127.0.0.1:1/triager-ssrf"
    response = vctx.get(vctx.build_url(params[0], probe))
    if response.status != control.status or vctx.body_changed(control.text, response.text):
        return vctx.result(
            status="Provável (parcial)",
            payload=probe,
            evidence=f"controle={control.status}; teste={response.status}; resposta diferente (sem confirmação OOB)",
            impact="O servidor pode ter tentado buscar URL controlada; sem callback OOB não é possível confirmar.",
            severity="medium",
            title="Possível SSRF",
            impact_demonstrated=False,
            prerequisites="listener out-of-band para confirmar callback",
            counter_evidence="diferença pode ser apenas validação de URL",
        )
    return vctx.result(
        status="Não reproduzida",
        payload=probe,
        evidence="sem diferença observável e sem callback OOB",
        impact="",
        severity=vctx.item.get("severity_declared") or "high",
        title="SSRF não reproduzido",
    )
