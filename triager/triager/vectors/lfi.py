"""Local file inclusion / path traversal validator."""

from __future__ import annotations

NAME = "lfi"


def validate(vctx) -> dict:
    params = vctx.params(["file", "path", "page", "template", "include"])
    param = params[0]
    marker = "root:x:0:0"
    # limite: 3 payloads de LFI.
    for payload in ("../../../../etc/passwd", "....//....//....//etc/passwd", "/etc/passwd%00"):
        response = vctx.get(vctx.build_url(param, payload))
        if marker in (response.text or ""):
            return vctx.result(
                status="Confirmada",
                payload=payload,
                evidence=f"conteúdo de /etc/passwd presente na resposta ({marker})",
                impact="Leitura de arquivos locais arbitrários do servidor.",
                severity="high",
                title="Local file inclusion",
            )
    return vctx.result(
        status="Não reproduzida",
        payload="../../../../etc/passwd",
        evidence="nenhum conteúdo de arquivo local observado",
        impact="",
        severity=vctx.item.get("severity_declared") or "high",
        title="LFI não reproduzido",
    )
