"""WAF-aware class policy shared by selection and AI planning."""

from __future__ import annotations

BASE_CLASSES = ["idor", "mass_assignment", "open_redirect", "cors", "csrf"]
INJECTION_CLASSES = ["xss", "sqli", "nosqli", "ssrf", "ssti", "lfi", "rce", "xxe"]


def for_target(recon: dict) -> list[str]:
    waf = (recon or {}).get("waf") or {}
    graphql = (recon or {}).get("graphql") or {}
    classes = list(BASE_CLASSES)
    if not waf.get("vendor"):
        classes.extend(INJECTION_CLASSES)
    if graphql.get("path"):
        classes.append("graphql")
    return classes
