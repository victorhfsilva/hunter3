"""GraphQL introspection / batching validator."""

from __future__ import annotations

import json

NAME = "graphql"


def validate(vctx) -> dict:
    endpoint = vctx.item["endpoint"]
    batching = vctx.post(
        endpoint,
        json_body=[{"query": "{ __typename }"}, {"query": "{ __typename }"}],
        headers={"Accept": "application/json"},
    )
    try:
        parsed = json.loads(batching.text)
    except ValueError:
        parsed = None
    if batching.status == 200 and isinstance(parsed, list) and len(parsed) >= 2:
        return vctx.result(
            status="Provável (parcial)",
            payload='[{"query":"{ __typename }"},{"query":"{ __typename }"}]',
            evidence=f"batching aceito; resposta é array com {len(parsed)} itens",
            impact="Batching amplifica consultas e pode contornar rate limit.",
            severity="low",
            title="GraphQL batching habilitado",
        )
    introspection = vctx.post(
        endpoint,
        json_body={"query": "query { __schema { queryType { name } mutationType { name } } }"},
        headers={"Accept": "application/json"},
    )
    if introspection.status == 200 and "__schema" in (introspection.text or ""):
        return vctx.result(
            status="Provável (parcial)",
            payload="{ __schema { queryType { name } mutationType { name } } }",
            evidence="introspection respondeu com __schema",
            impact="Schema exposto; revisar mutations e autorização manualmente.",
            severity="low",
            title="GraphQL introspection habilitada",
        )
    return vctx.result(
        status="Não reproduzida",
        payload="{ __typename }",
        evidence="batching/introspection não observados",
        impact="",
        severity=vctx.item.get("severity_declared") or "low",
        title="GraphQL não reproduzido",
    )
