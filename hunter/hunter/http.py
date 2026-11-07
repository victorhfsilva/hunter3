"""Single HTTP client: scope gate, rate limit, retries, counters, artifacts."""

from __future__ import annotations

import json
import os
import socket
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urljoin, urlsplit

try:  # pragma: no cover - exercised only when requests is unavailable
    import requests
except Exception:  # pragma: no cover
    requests = None

from .budget import BudgetExceeded
from .scope import Scope



def _install_test_resolver() -> None:
    """Optional loopback mapping for acceptance tests (HUNTER_RESOLVE_HOSTS)."""
    raw = os.environ.get("HUNTER_RESOLVE_HOSTS", "")
    mapping = {}
    for item in raw.split(","):
        if "=" in item:
            host, address = item.split("=", 1)
            host, address = host.strip().lower(), address.strip()
            if host and address:
                mapping[host] = address
    if not mapping:
        return
    original = socket.getaddrinfo

    def patched(host, port, family=0, type=0, proto=0, flags=0):
        key = host.decode("ascii", "ignore") if isinstance(host, bytes) else host
        if isinstance(key, str) and key.lower() in mapping:
            return original(mapping[key.lower()], port, family, type, proto, flags)
        return original(host, port, family, type, proto, flags)

    socket.getaddrinfo = patched


_install_test_resolver()

CONNECT_TIMEOUT = 5
READ_TIMEOUT = 15
MAX_ATTEMPTS = 2
MAX_PER_ENDPOINT = 15


@dataclass
class Response:
    method: str
    url: str
    status: int = 0
    headers: dict = field(default_factory=dict)
    text: str = ""
    elapsed: float = 0.0
    error: str = ""
    redirect_external: str = ""
    redirect_followed: bool = False
    request_headers: dict = field(default_factory=dict)
    request_body: str = ""

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 400

    @property
    def blocked(self) -> bool:
        return self.status in (403, 429) or self.status == 0

    def body_snippet(self, limit: int = 4096) -> str:
        return (self.text or "")[:limit]


class ScopeViolation(Exception):
    def __init__(self, url: str, reason: str):
        super().__init__(f"{url}: {reason}")
        self.url = url
        self.reason = reason


def endpoint_key(method: str, url: str) -> str:
    try:
        path = urlsplit(url).path or "/"
    except ValueError:
        path = "/"
    return f"{method.upper()} {path}"


class HttpClient:
    def __init__(self, ctx, host: str, rate: float = 5.0, verbose: bool = False, max_per_endpoint: int = MAX_PER_ENDPOINT):
        self.ctx = ctx
        self.host = host
        self.max_per_endpoint = max(1, int(max_per_endpoint))
        self.scope: Scope = ctx.scopes[host]
        self.budget = ctx.budget
        self.rate = max(0.1, float(rate))
        self.verbose = verbose
        self.logger = ctx.logger(host)
        self.artifacts = ctx.artifacts_dir(host)
        self.artifacts.mkdir(parents=True, exist_ok=True)
        self.sequence = 0
        self._last_request_at: dict[str, float] = {}
        self.endpoint_counts: dict[str, int] = {}
        self.endpoint_strikes: dict[str, int] = {}
        self.endpoint_blocked: set[str] = set()
        self.redact_values: list[str] = []
        self.session = requests.Session() if requests else None
        self.phase = "recon"

    # ------------------------------------------------------------- primitives
    def set_phase(self, phase: str) -> None:
        self.phase = phase

    def add_redaction(self, value: str) -> None:
        if value and len(value) >= 3 and value not in self.redact_values:
            self.redact_values.append(value)

    def _redact(self, text: str) -> str:
        result = text or ""
        for value in self.redact_values:
            result = result.replace(value, "[REDACTED]")
        return result

    def _rate_limit(self, host: str) -> None:
        interval = 1.0 / self.rate
        now = time.monotonic()
        last = self._last_request_at.get(host, 0.0)
        wait = last + interval - now
        if wait > 0:
            time.sleep(min(wait, 10.0))
        self._last_request_at[host] = time.monotonic()

    def _save_artifact(self, response: Response) -> None:
        self.sequence += 1
        safe = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in urlsplit(response.url).path)[:80] or "root"
        path = self.artifacts / f"{self.sequence:04d}_{response.method}_{safe}.txt"
        request_body = self._redact(response.request_body)[:4096]
        request_headers = {
            key: ("[REDACTED]" if key.lower() in ("authorization", "cookie") else value)
            for key, value in response.request_headers.items()
        }
        text = (
            f"=== {self.ctx.run_id} artifact #{self.sequence} ===\n"
            f"time_utc: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}\n"
            f"request: {response.method} {response.url}\n"
            f"request_headers: {json.dumps(request_headers, ensure_ascii=False)}\n"
            f"request_body: {request_body}\n"
            f"error: {response.error}\n"
            f"response_status: {response.status}\n"
            f"response_headers: {json.dumps(response.headers, ensure_ascii=False)}\n"
            f"elapsed_seconds: {response.elapsed:.4f}\n"
            "response_body:\n"
            f"{self._redact(response.text[:8192])}\n"
        )
        try:
            path.write_text(text, encoding="utf-8")
        except OSError:
            pass

    def _record_strike(self, key: str, response: Response) -> None:
        if response.blocked:
            self.endpoint_strikes[key] = self.endpoint_strikes.get(key, 0) + 1
            if self.endpoint_strikes[key] >= 3:
                self.endpoint_blocked.add(key)
                self.logger.info("endpoint bloqueado (3-strikes): %s", key)
                self.ctx.add_skip(self.host, f"endpoint {key}", "3-strikes/blocked")
        elif response.status and response.status < 500:
            self.endpoint_strikes[key] = 0

    def is_blocked(self, url: str, method: str = "GET") -> bool:
        return endpoint_key(method, url) in self.endpoint_blocked

    # ----------------------------------------------------------------- request
    def request(
        self,
        method: str,
        url: str,
        headers: dict | None = None,
        data: str | bytes | None = None,
        json_body: dict | None = None,
        follow_redirects: bool = True,
    ) -> Response:
        method = method.upper()
        allowed, reason = self.scope.check(url)
        if not allowed:
            self.ctx.add_out_of_scope(self.host, url, reason)
            raise ScopeViolation(url, reason)

        key = endpoint_key(method, url)
        if key in self.endpoint_blocked:
            raise BudgetExceeded(f"endpoint bloqueado: {key}")
        if self.endpoint_counts.get(key, 0) >= self.max_per_endpoint:
            raise BudgetExceeded(f"teto de {self.max_per_endpoint} requisições por endpoint: {key}")

        request_headers = {"User-Agent": "hunter/1.0 (non-destructive; scoped)"}
        if headers:
            request_headers.update(headers)
        body_text = ""
        payload = data
        if json_body is not None:
            body_text = json.dumps(json_body, ensure_ascii=False)
            payload = body_text.encode("utf-8")
            request_headers.setdefault("Content-Type", "application/json")
        elif isinstance(data, str):
            body_text = data

        response = None
        # limite: MAX_ATTEMPTS (2) tentativas por requisição.
        for attempt in range(MAX_ATTEMPTS):
            self.budget.check_target()
            self._rate_limit(urlsplit(url).hostname or self.host)
            self.budget.consume_request(self.phase, key)
            self.endpoint_counts[key] = self.endpoint_counts.get(key, 0) + 1
            started = time.monotonic()
            try:
                response = self._send(method, url, request_headers, payload, body_text)
            except Exception as exc:
                response = Response(
                    method=method,
                    url=url,
                    status=0,
                    error=str(exc),
                    elapsed=time.monotonic() - started,
                    request_headers=request_headers,
                    request_body=body_text,
                )
            response.request_headers = request_headers
            response.request_body = body_text
            if attempt == 0 and response.status in (429, 500, 502, 503, 504):
                time.sleep(1.0)
                continue
            break

        assert response is not None
        self._record_strike(key, response)
        self._save_artifact(response)

        if follow_redirects and response.status in (301, 302, 303, 307, 308):
            location = response.headers.get("location", "")
            if location:
                target = urljoin(url, location)
                allowed, reason = self.scope.check(target)
                if not allowed:
                    response.redirect_external = target
                    self.ctx.add_out_of_scope(self.host, target, f"redirect externo: {reason}")
                    self.logger.info("redirect externo registrado: %s", target)
                else:
                    followed = self.request("GET", target, headers=headers, follow_redirects=False)
                    followed.redirect_followed = True
                    return followed
        if self.verbose:
            self.logger.info("%s %s -> %s (%.3fs)", method, url, response.status, response.elapsed)
        return response

    def get(self, url: str, **kwargs) -> Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> Response:
        return self.request("POST", url, **kwargs)

    # -------------------------------------------------------------- transports
    def _send(self, method: str, url: str, headers: dict, payload, body_text: str) -> Response:
        if requests is not None:
            try:
                raw = self.session.request(
                    method,
                    url,
                    headers=headers,
                    data=payload,
                    timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
                    allow_redirects=False,
                )
                return Response(
                    method=method,
                    url=url,
                    status=raw.status_code,
                    headers={k.lower(): v for k, v in raw.headers.items()},
                    text=raw.text or "",
                    elapsed=raw.elapsed.total_seconds() if raw.elapsed else 0.0,
                )
            except Exception as exc:
                return Response(method=method, url=url, status=0, error=f"{type(exc).__name__}: {exc}")
        return self._send_urllib(method, url, headers, payload)

    def _send_urllib(self, method: str, url: str, headers: dict, payload) -> Response:  # pragma: no cover
        import urllib.error
        import urllib.request

        request = urllib.request.Request(url, data=payload, headers=headers, method=method)
        started = time.monotonic()
        try:
            with urllib.request.urlopen(request, timeout=READ_TIMEOUT) as raw:
                body = raw.read(1_000_000)
                return Response(
                    method=method,
                    url=url,
                    status=getattr(raw, "status", raw.getcode()),
                    headers={k.lower(): v for k, v in raw.headers.items()},
                    text=body.decode("utf-8", "replace"),
                    elapsed=time.monotonic() - started,
                )
        except urllib.error.HTTPError as exc:
            body = exc.read(1_000_000) if hasattr(exc, "read") else b""
            return Response(
                method=method,
                url=url,
                status=exc.code,
                headers={k.lower(): v for k, v in exc.headers.items()} if exc.headers else {},
                text=body.decode("utf-8", "replace"),
                elapsed=time.monotonic() - started,
            )
        except Exception as exc:
            return Response(method=method, url=url, status=0, error=f"{type(exc).__name__}: {exc}", elapsed=time.monotonic() - started)
