"""Open redirect validator."""

from __future__ import annotations

NAME = "open_redirect"


def validate(vctx) -> dict:
    params = vctx.params(["next", "url", "redirect", "return", "dest", "target"])
    marker = vctx.marker()
    target = f"https://evil.invalid/{marker}"
    for param in params[:3]:
        response = vctx.get(vctx.build_url(param, target))
        location = response.headers.get("location", "") or response.redirect_external
        if response.redirect_external or (location.startswith("http") and "evil.invalid" in location):
            return vctx.result(
                status="Confirmada",
                payload=f"{param}={target}",
                evidence=f"Location externo observado: {location}; status={response.status}",
                impact="Redirecionamento para domínio arbitrário, útil em phishing e fluxos OAuth.",
                severity="medium",
                title="Open redirect",
                method="GET",
            )
    return vctx.result(
        status="Não reproduzida",
        payload="",
        evidence="nenhum redirecionamento externo observado",
        impact="",
        severity=vctx.item.get("severity_declared") or "medium",
        title="Open redirect não reproduzido",
    )
