"""CSRF validator (heuristic, never changes state)."""

from __future__ import annotations

import re

NAME = "csrf"


def validate(vctx) -> dict:
    response = vctx.get(vctx.item["endpoint"])
    body = response.text or ""
    forms = re.findall(r"<form\b[^>]*>(.*?)</form>", body, re.IGNORECASE | re.DOTALL)
    if not forms:
        return vctx.result(
            status="Não reproduzida",
            payload="",
            evidence="nenhum formulário observado",
            impact="",
            severity=vctx.item.get("severity_declared") or "medium",
            title="CSRF não aplicável",
        )
    has_token = any(
        re.search(r"csrf|xsrf|authenticity_token|__requestverificationtoken", form, re.IGNORECASE)
        for form in forms
    )
    cookies = [value for key, value in response.headers.items() if key == "set-cookie"]
    same_site_none = any("samesite=none" in cookie.lower() for cookie in cookies)
    if not has_token:
        return vctx.result(
            status="Provável (parcial)",
            payload="formulário sem token anti-CSRF",
            evidence=f"form(s)={len(forms)}; token=ausente; SameSite=None={same_site_none}",
            impact="Se o formulário alterar estado, um site externo pode induzir a vítima a enviá-lo.",
            severity="medium" if same_site_none else "low",
            title="Formulário sem token anti-CSRF",
            impact_demonstrated=False,
            counter_evidence="ação do formulário não foi executada (não destrutivo)",
        )
    return vctx.result(
        status="Não reproduzida",
        payload="",
        evidence="token anti-CSRF presente",
        impact="",
        severity=vctx.item.get("severity_declared") or "medium",
        title="CSRF não reproduzido",
    )
