"""Phase 3 — controlled validation on the authorised target."""

from __future__ import annotations

import json
import time
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .budget import BudgetExceeded
from .http import Response, ScopeViolation
from .state import atomic_write_text, utcnow
from .vectors import get as get_vector

MAX_REQUESTS_PER_CANDIDATE = 10
MAX_PAYLOADS_PER_VECTOR = 5
CONSECUTIVE_BLOCKED_LIMIT = 3


def _redact_headers(headers: dict) -> dict:
    result = {}
    for key, value in (headers or {}).items():
        if key.lower() in ("authorization", "cookie", "set-cookie", "x-api-key", "proxy-authorization"):
            result[key] = "[REDACTED]"
        else:
            result[key] = value
    return result


def body_changed(first: str, second: str, min_ratio: float = 0.01) -> bool:
    import re

    a = re.sub(r"\s+", " ", first or "").strip()
    b = re.sub(r"\s+", " ", second or "").strip()
    if a == b:
        return False
    if not a or not b:
        return True
    common = sum(1 for x, y in zip(a, b) if x == y)
    return (1.0 - common / max(len(a), len(b))) >= min_ratio


class ValidatorContext:
    def __init__(self, ctx, sub: str, item: dict, client):
        self.ctx = ctx
        self.sub = sub
        self.item = item
        self.client = client
        self.budget = ctx.budget
        self.oob_url = getattr(ctx.args, "oob_url", None) or ""
        self.artifacts = ctx.artifacts_dir(sub) / item["id"]
        self.requests = 0
        self.max_requests = MAX_REQUESTS_PER_CANDIDATE
        self.max_payloads = MAX_PAYLOADS_PER_VECTOR
        self._baseline: Response | None = None
        self.last_response: Response | None = None
        self.last_method = "GET"
        self.last_url = ""
        client.candidate_id = item["id"]

    # ------------------------------------------------------------------ helpers
    def marker(self) -> str:
        import secrets

        return "tri" + secrets.token_hex(4)

    def params(self, fallback: list[str]) -> list[str]:
        params: list[str] = []
        if self.item.get("param"):
            params.append(self.item["param"])
        try:
            for key, _value in parse_qsl(urlsplit(self.item.get("endpoint", "")).query, keep_blank_values=True):
                if key and key not in params:
                    params.append(key)
        except ValueError:
            pass
        for item in fallback:
            if item not in params:
                params.append(item)
        return params

    def build_url(self, param: str, value: str) -> str:
        parts = urlsplit(self.item["endpoint"])
        query = [(key, val) for key, val in parse_qsl(parts.query, keep_blank_values=True) if key != param]
        query.append((param, value))
        return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query, doseq=True), ""))

    def request(self, method: str, url: str, **kwargs) -> Response:
        if self.requests >= self.max_requests:
            raise BudgetExceeded("teto de 10 requisições por candidata atingido")
        self.requests += 1
        response = self.client.request(method, url, candidate_id=self.item["id"], **kwargs)
        self.last_response = response
        self.last_method = method.upper()
        self.last_url = response.url or url
        return response

    def get(self, url: str, **kwargs) -> Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> Response:
        return self.request("POST", url, **kwargs)

    def baseline(self) -> Response:
        if self._baseline is None:
            self._baseline = self.get(self.item["endpoint"])
        return self._baseline

    def body_changed(self, first: str, second: str, min_ratio: float = 0.01) -> bool:
        return body_changed(first, second, min_ratio)

    def snippet(self, text: str, marker: str, width: int = 120) -> str:
        if not text or not marker:
            return ""
        index = text.find(marker)
        if index < 0:
            return ""
        start = max(0, index - width // 2)
        return text[start : start + width].replace("\n", " ")

    def result(self, **kwargs) -> dict:
        base = {
            "status": "Não reproduzida",
            "payload": "",
            "evidence": "",
            "impact": "",
            "severity": self.item.get("severity_declared") or "low",
            "title": "",
            "method": self.item.get("method", "GET"),
            "impact_demonstrated": True,
            "prerequisites": "",
            "counter_evidence": "",
            "severity_change": "",
            "confidence": "",
            "requests": self.requests,
        }
        base.update(kwargs)
        base["requests"] = self.requests
        return base

    # ---------------------------------------------------------------- artifacts
    def save_artifacts(self, result: dict) -> None:
        response = self.last_response
        if response is None:
            return
        self.artifacts.mkdir(parents=True, exist_ok=True)
        headers = _redact_headers(response.request_headers)
        req_text = f"{self.last_method} {self.last_url}\n" + "".join(f"{key}: {value}\n" for key, value in headers.items())
        if response.request_body:
            req_text += "\n" + self.client.redact(response.request_body[:4000])
        resp_headers = _redact_headers(response.headers)
        resp_text = f"HTTP {response.status}\n" + "".join(f"{key}: {value}\n" for key, value in resp_headers.items())
        resp_text += "\n" + self.client.redact((response.text or "")[:4000])
        meta = {
            "candidate_id": self.item["id"],
            "class": self.item.get("type"),
            "endpoint": self.item.get("endpoint"),
            "payload": result.get("payload", ""),
            "status": result.get("status"),
            "timestamp_utc": utcnow(),
            "duration_seconds": round(response.elapsed, 4),
            "http_status": response.status,
            "requests_for_candidate": self.requests,
            "curl_equivalent": f"curl -i -X {self.last_method} '{self.last_url}'",
            "note": "valores sensíveis redigidos",
        }
        atomic_write_text(self.artifacts / "req.txt", req_text)
        atomic_write_text(self.artifacts / "resp.txt", resp_text)
        atomic_write_text(self.artifacts / "meta.json", json.dumps(meta, indent=2, ensure_ascii=False) + "\n")


def run_validation(ctx, sub: str, client, batch: list[dict]) -> None:
    state = ctx.subs[sub]
    phase = state["phases"]["validate"]
    phase["status"] = "running"
    phase["started_utc"] = phase.get("started_utc") or utcnow()
    ctx.budget.mark_phase("validate")
    if not batch:
        phase["status"] = "done"
        phase["finished_utc"] = utcnow()
        ctx.add_skip(sub, "validate", "nenhuma candidata ativa no lote")
        ctx.flush(sub)
        return
    consecutive_blocked = 0
    for item in batch:
        if item.get("status") in ("Confirmada", "Provável (parcial)", "Não reproduzida", "Falso-positivo", "Bloqueada"):
            continue
        try:
            ctx.budget.check_phase("validate")
        except BudgetExceeded as exc:
            ctx.add_skip(sub, "validate", str(exc))
            phase["status"] = "partial"
            break
        if item.get("flag") != "active":
            continue
        vector = get_vector(item.get("type", ""))
        if vector is None:
            item["status"] = "Não testada (sem validador)"
            ctx.flush(sub)
            continue
        vctx = ValidatorContext(ctx, sub, item, client)
        result = None
        try:
            result = vector.validate(vctx)
        except ScopeViolation as exc:
            item["status"] = "Fora de escopo"
            item["validation"] = {"status": "Fora de escopo", "evidence": exc.reason, "requests": vctx.requests}
            ctx.add_out_of_scope(sub, exc.url, exc.reason)
            ctx.flush(sub)
            continue
        except BudgetExceeded as exc:
            if "por candidata" in str(exc):
                item["status"] = "Bloqueada"
                item["validation"] = {"status": "Bloqueada", "evidence": str(exc), "requests": vctx.requests}
                consecutive_blocked += 1
            else:
                ctx.add_skip(sub, "validate", str(exc))
                phase["status"] = "partial"
                ctx.flush(sub)
                break
        except Exception as exc:
            result = vctx.result(
                status="Não reproduzida",
                payload="",
                evidence=f"erro interno do validador: {type(exc).__name__}: {exc}",
                title="Validação não concluída",
            )
            ctx.logger(sub).warning("validador %s falhou em %s: %s", item.get("type"), item.get("endpoint"), exc)
        if result:
            status = result.get("status", "Não reproduzida")
            item["status"] = status
            item["validation"] = {
                "status": status,
                "payload": result.get("payload", ""),
                "evidence": result.get("evidence", ""),
                "impact": result.get("impact", ""),
                "requests": vctx.requests,
                "at_utc": utcnow(),
            }
            finding = {
                "class": item.get("type"),
                "title": result.get("title") or f"{item.get('type')} em {item.get('endpoint')}",
                "endpoint": item.get("endpoint", ""),
                "method": result.get("method") or item.get("method", "GET"),
                "param": item.get("param", ""),
                "payload": result.get("payload", ""),
                "severity": result.get("severity") or item.get("severity_declared") or "low",
                "status": status,
                "evidence": result.get("evidence", ""),
                "impact": result.get("impact", ""),
                "impact_demonstrated": result.get("impact_demonstrated", True),
                "prerequisites": result.get("prerequisites", ""),
                "counter_evidence": result.get("counter_evidence", ""),
                "severity_change": result.get("severity_change", ""),
                "tool_origin": item.get("tool_origin", ""),
                "sources": item.get("sources", []),
                "candidate_id": item["id"],
                "requests": vctx.requests,
                "requests_spent": vctx.requests,
            }
            if status in ("Confirmada", "Provável (parcial)"):
                vctx.save_artifacts(result)
            ctx.add_finding(sub, finding)
            if status in ("Bloqueada",):
                consecutive_blocked += 1
            elif status in ("Confirmada", "Provável (parcial)", "Não reproduzida", "Falso-positivo"):
                consecutive_blocked = 0
            ctx.flush(sub)
            if consecutive_blocked >= CONSECUTIVE_BLOCKED_LIMIT:
                ctx.add_skip(sub, "validate", "3 candidatas consecutivas bloqueadas")
                phase["status"] = "partial"
                break
            if ctx.budget.requests_by_candidate.get(item["id"], 0) >= MAX_REQUESTS_PER_CANDIDATE:
                item["status"] = item.get("status") or "Bloqueada"
    if phase["status"] != "partial":
        phase["status"] = "done"
    phase["finished_utc"] = utcnow()
    ctx.flush(sub)
