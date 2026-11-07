"""SQL injection validator (error / boolean, no data extraction)."""

from __future__ import annotations

import re

NAME = "sqli"
SQL_ERROR_RE = re.compile(
    r"SQL syntax|mysql_fetch|mysqli|PostgreSQL|SQLite|ORA-\d{4,}|ODBC|SQLSTATE|unclosed quotation|quoted string",
    re.IGNORECASE,
)


def validate(vctx) -> dict:
    params = vctx.params(["id", "q", "search"])
    param = params[0]
    control = vctx.get(vctx.build_url(param, "1"))
    true_response = None
    false_response = None
    # limite: 3 payloads de SQLi.
    for payload in ("'", "' AND '1'='1", "' AND '1'='2"):
        response = vctx.get(vctx.build_url(param, payload))
        error = SQL_ERROR_RE.search(response.text or "")
        if error and not SQL_ERROR_RE.search(control.text or ""):
            return vctx.result(
                status="Confirmada",
                payload=payload,
                evidence=f"assinatura SQL na resposta: {error.group(0)}; status={response.status}",
                impact="Entrada chega a uma consulta SQL; injeção confirmada por erro (sem extração de dados).",
                severity="high",
                title="SQL injection (erro)",
            )
        if payload.endswith("'1'='1"):
            true_response = response
        if payload.endswith("'1'='2"):
            false_response = response
    if true_response and false_response and true_response.status == false_response.status == 200:
        if vctx.body_changed(true_response.text, false_response.text):
            return vctx.result(
                status="Provável (parcial)",
                payload="' AND '1'='1 / ' AND '1'='2",
                evidence="corpo difere entre condição verdadeira e falsa",
                impact="Comportamento booleano consistente com injeção SQL; requer confirmação manual.",
                severity="medium",
                title="SQL injection booleana suspeita",
                impact_demonstrated=False,
                counter_evidence="conteúdo dinâmico pode causar diferença",
            )
    return vctx.result(
        status="Não reproduzida",
        payload="",
        evidence="sem erro SQL e sem diferença booleana estável",
        impact="",
        severity=vctx.item.get("severity_declared") or "high",
        title="SQLi não reproduzido",
    )
