"""Phase 2 — WAF-aware selection of a small, high-value test surface."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from . import classes as class_policy
from .state import utcnow

HIGH_VALUE = re.compile(
    r"account|user|order|billing|invoice|payment|token|password|reset|admin|upload|export|role|settings|checkout|search|login|signin|auth",
    re.IGNORECASE,
)
STATIC = re.compile(r"\.(?:js|css|png|jpe?g|gif|svg|ico|woff2?|ttf|map|txt|xml|json)$", re.IGNORECASE)


SOURCE_BONUS = {"ai": 4, "openapi": 3, "form": 2, "graphql": 2, "sourcemap": 1, "robots": 1, "sitemap": 1}


def _score(endpoint: dict) -> int:
    url = endpoint.get("url", "")
    path = urlsplit(url).path or ""
    score = 0
    if HIGH_VALUE.search(path):
        score += 5
    if re.search(r"/\d+(?:/|$)", path):
        score += 3
    if re.search(r"[?&](?:id|user_id|order_id|account|uid)=", url, re.IGNORECASE):
        score += 4
    params = endpoint.get("params") or []
    score += min(len(params), 3)
    if params:
        score += 2
    if endpoint.get("method", "GET").upper() in ("POST", "PUT", "PATCH"):
        score += 2
    if endpoint.get("source") == "js":
        score += 1
    source = str(endpoint.get("source", ""))
    for key, bonus in SOURCE_BONUS.items():
        if key in source:
            score += bonus
    if endpoint.get("ai_classes"):
        score += 3
    return score


def run_select(ctx, host: str, client) -> dict:
    state = ctx.targets[host]
    ctx.budget.check_phase("select")
    ctx.budget.mark_phase("select")
    phase = state["phases"]["select"]
    phase["status"] = "running"
    phase["started_utc"] = phase.get("started_utc") or utcnow()
    recon = state.get("recon", {})
    waf = recon.get("waf", {}) or {}
    graphql = recon.get("graphql", {}) or {}
    classes = class_policy.for_target(recon)
    settings = ctx.settings

    candidates = []
    for endpoint in recon.get("api_endpoints", []):
        url = endpoint.get("url", "")
        allowed, _ = client.scope.check(url)
        if not allowed:
            ctx.add_out_of_scope(host, url, "endpoint fora do host do alvo")
            continue
        if STATIC.search(urlsplit(url).path or ""):
            continue
        if "{" in url or "}" in url:
            continue
        item = dict(endpoint)
        item["score"] = _score(item)
        merged_classes = list(classes)
        for value in item.get("ai_classes") or []:
            if value in classes and value not in merged_classes:
                merged_classes.append(value)
        graphql_path = (graphql or {}).get("path") or ""
        if "graphql" in merged_classes and graphql_path and graphql_path not in urlsplit(url).path:
            merged_classes.remove("graphql")
        item["classes"] = merged_classes
        item["stop"] = {"max_requests": settings.max_requests_per_endpoint, "strikes": 3}
        candidates.append(item)

    candidates.sort(key=lambda item: (item.get("score", 0), item.get("source") == "js"), reverse=True)
    unique = []
    seen = set()
    for item in candidates:
        parts = urlsplit(item.get("url", ""))
        key = (item.get("method", "GET").upper(), parts.scheme, parts.netloc, parts.path)
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)

    remaining_requests = max(0, ctx.budget.max_requests - ctx.budget.requests_target)
    remaining_seconds = ctx.budget.target_remaining()
    if remaining_requests >= 100 and remaining_seconds >= 600:
        limit = settings.max_endpoints
        mode = f"top {limit} ({settings.profile})"
    elif remaining_requests >= 30 and remaining_seconds >= 180:
        limit = min(8, settings.max_endpoints)
        mode = f"top {limit} (orçamento médio)"
    else:
        limit = 1
        mode = "top 1 (orçamento reduzido)"
    selected = unique[:limit]

    checkpoint = {
        "at_utc": utcnow(),
        "requests_used": ctx.budget.requests_target,
        "requests_remaining": remaining_requests,
        "seconds_remaining": round(remaining_seconds, 2),
        "all_endpoints_in_scope": all(client.scope.check(item["url"])[0] for item in selected),
        "candidates": len(unique),
        "selected_count": len(selected),
        "mode": mode,
        "selection_criteria": (
            "valor de conta/pedido/pagamento/reset/admin + IDs/parâmetros + origem (IA/OpenAPI/forms); "
            f"teto {settings.max_requests_per_endpoint} req e 3-strikes"
        ),
        "classes": classes,
        "waf_vendor": waf.get("vendor", ""),
        "profile": settings.profile,
        "ai_endpoints": sum(1 for item in selected if item.get("source") == "ai"),
    }
    phase["checkpoint"] = checkpoint
    state["endpoints"] = selected
    ctx.add_skip(host, "select", f"seleção {mode}: {len(selected)} endpoint(s) de {len(unique)} candidato(s)")
    phase["status"] = "done"
    phase["finished_utc"] = utcnow()
    ctx.flush(host)
    return {"endpoints": selected, "classes": classes, "checkpoint": checkpoint}
