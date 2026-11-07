"""IDOR / BOLA validator (limited without a second account)."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

NAME = "idor"
SENSITIVE_RE = re.compile(r'"(?:email|role|order|account|user|billing|invoice|price)"\s*:', re.IGNORECASE)


def validate(vctx) -> dict:
    endpoint = vctx.item.get("endpoint", "")
    original = vctx.get(endpoint)
    if original.status != 200:
        return vctx.result(
            status="Não reproduzida",
            payload="",
            evidence=f"baseline status={original.status}",
            impact="",
            severity=vctx.item.get("severity_declared") or "medium",
            title="IDOR não reproduzido",
        )
    path = urlsplit(endpoint).path
    trials = []
    match = re.search(r"/(\d+)(?=/|$)", path)
    if match:
        base = int(match.group(1))
        for delta in (1, -1):
            if base + delta <= 0:
                continue
            replaced = re.sub(r"/\d+(?=/|$)", f"/{base + delta}", path, count=1)
            trials.append(endpoint.replace(path, replaced, 1))
    if not trials:
        return vctx.result(
            status="Não reproduzida",
            payload="",
            evidence="candidata sem identificador numérico no path",
            impact="",
            severity=vctx.item.get("severity_declared") or "medium",
            title="IDOR não aplicável",
        )
    for trial in trials[:2]:
        response = vctx.get(trial)
        if response.status == 200 and response.text != original.text and (
            SENSITIVE_RE.search(response.text) or response.text.strip().startswith("{")
        ):
            return vctx.result(
                status="Provável (parcial)",
                payload="id alternativo",
                evidence=f"original={original.status} ({len(original.text)}B); alternativo={response.status} ({len(response.text)}B); corpo diferente",
                impact="A resposta mudou ao trocar o identificador; confirmar com duas contas se o dado pertence a outro usuário.",
                severity="medium",
                title="Possível IDOR/BOLA",
                impact_demonstrated=False,
                prerequisites="duas contas autenticadas para provar propriedade do objeto",
                counter_evidence="diferença de corpo não prova acesso a dado de terceiro",
            )
    return vctx.result(
        status="Não reproduzida",
        payload="id alternativo",
        evidence="sem diferença relevante entre identificadores",
        impact="",
        severity=vctx.item.get("severity_declared") or "medium",
        title="IDOR não reproduzido",
    )
