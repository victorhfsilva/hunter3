"""Vector registry."""

from __future__ import annotations

from . import cors, csrf, graphql, idor, lfi, nosqli, open_redirect, rce, sqli, ssrf, ssti, xss, xxe

VALIDATORS = {
    "xss": xss,
    "sqli": sqli,
    "nosqli": nosqli,
    "ssrf": ssrf,
    "lfi": lfi,
    "rfi": lfi,
    "rce": rce,
    "open_redirect": open_redirect,
    "idor": idor,
    "cors": cors,
    "csrf": csrf,
    "ssti": ssti,
    "xxe": xxe,
    "graphql": graphql,
}


def get(canonical_type: str):
    return VALIDATORS.get(canonical_type)
