"""Triage rules: out_of_scope / no_active_test / low_priority / active."""

from __future__ import annotations

from urllib.parse import urlsplit

from .normalize import ACTIVE_TYPES, normalize_path

LOW_PRIORITY_TYPES = {"headers", "tech", "misconfig", "endpoint_internal", "other"}


def candidate_host(item: dict) -> str:
    host = (item.get("host") or "").strip().lower()
    if host:
        return host
    endpoint = item.get("endpoint") or ""
    if "://" in endpoint:
        try:
            return (urlsplit(endpoint).hostname or "").lower()
        except ValueError:
            return ""
    return ""


def classify(item: dict, allowed_hosts: set[str], inferred_host: str | None, has_targets: bool) -> tuple[str, str]:
    """Return (flag, reason)."""
    canonical = item.get("type", "other")
    host = candidate_host(item)
    endpoint = item.get("endpoint") or ""

    if canonical == "secret":
        return "no_active_test", "segredo/credencial: registrado sem uso ou validação"
    if has_targets:
        if not host or host not in allowed_hosts:
            return "out_of_scope", f"host fora de --targets ({host or 'sem host'})"
    else:
        if inferred_host and host and host != inferred_host:
            return "out_of_scope", f"host difere do alvo inferido ({host})"
    if canonical in LOW_PRIORITY_TYPES:
        return "low_priority", "baixo impacto / sem PoC ativo"
    if canonical in ACTIVE_TYPES:
        if not (endpoint.startswith("http://") or endpoint.startswith("https://")):
            return "no_active_test", "endpoint não é URL HTTP(S) validável automaticamente"
        return "active", "validável"
    return "low_priority", "classe sem validador ativo"


def apply(candidates: list[dict], allowed_hosts: set[str], inferred_host: str | None, has_targets: bool) -> dict:
    counts = {"active": 0, "out_of_scope": 0, "no_active_test": 0, "low_priority": 0}
    for item in candidates:
        if item.get("status") in ("Confirmada", "Provável (parcial)", "Não reproduzida", "Falso-positivo", "Bloqueada"):
            continue
        flag, reason = classify(item, allowed_hosts, inferred_host, has_targets)
        prior = item.get("flag")
        if prior == "out_of_scope":
            flag = "out_of_scope"
            reason = item.get("triage_reason") or reason
        item["flag"] = flag
        item["triage_reason"] = reason
        counts[flag] = counts.get(flag, 0) + 1
        if flag == "out_of_scope":
            item["status"] = "Fora de escopo"
        elif item.get("status") in ("", "pending") and flag != "active":
            item["status"] = "pending"
    return counts


def select_batch(candidates: list[dict], limit: int) -> list[dict]:
    eligible = [
        item
        for item in candidates
        if item.get("flag") == "active"
        and item.get("status") not in ("Confirmada", "Provável (parcial)", "Não reproduzida", "Falso-positivo", "Bloqueada")
    ]
    eligible.sort(key=lambda item: (item.get("score", 0), item.get("severity_declared", "")), reverse=True)
    return eligible[: max(0, int(limit))]


def out_of_scope_rows(candidates: list[dict]) -> list[dict]:
    return [item for item in candidates if item.get("flag") == "out_of_scope"]


def secret_rows(candidates: list[dict]) -> list[dict]:
    return [item for item in candidates if item.get("flag") == "no_active_test" and item.get("type") == "secret"]


def low_priority_rows(candidates: list[dict]) -> list[dict]:
    return [item for item in candidates if item.get("flag") == "low_priority"]
