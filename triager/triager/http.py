"""Single HTTP choke point: allowlist, rate limit, retries, captures."""

from __future__ import annotations

import json
import os
import socket
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

try:  # pragma: no cover - only when requests is unavailable
    import requests
except Exception:  # pragma: no cover
    requests = None

from .budget import BudgetExceeded
from .scope import Scope

CONNECT_TIMEOUT = 5
READ_TIMEOUT = 15
MAX_ATTEMPTS = 2
MAX_PER_ENDPOINT = 15


def install_test_resolver() -> None:
    """Optional loopback mapping for acceptance tests (TRIAGER_RESOLVE_HOSTS)."""
    raw = os.environ.get("TRIAGER_RESOLVE_HOSTS", "")
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


install_test_resolver()


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
    request_headers: dict = field(default_factory=dict)
    request_body: str = ""

    @property
    def blocked(self) -> bool:
        return self.status in (403, 429) or self.status == 0

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 400


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
    def __init__(self, scope: Scope, budget, logger=None, phase: str = "validate", on_out_of_scope=None):
        self.scope = scope
        self.budget = budget
        self.logger = logger
        self.phase = phase
        self.on_out_of_scope = on_out_of_scope
        self.session = requests.Session() if requests else None
        self.redact_values: list[str] = []
        self.endpoint_counts: dict[str, int] = {}
        self.endpoint_strikes: dict[str, int] = {}
        self.endpoint_blocked: set[str] = set()
        self.candidate_id = ""

    # ----------------------------------------------------------------- helpers
    def add_redaction(self, value: str) -> None:
        if value and len(value) >= 3 and value not in self.redact_values:
            self.redact_values.append(value)

    def redact(self, text: str) -> str:
        result = text or ""
        for value in self.redact_values:
            result = result.replace(value, "[REDACTED]")
        return result

    def _log(self, level: str, message: str, *args) -> None:
        if self.logger:
            getattr(self.logger, level)(message, *args)

    def _out_of_scope(self, url: str, reason: str) -> None:
        if self.on_out_of_scope:
            self.on_out_of_scope(url, reason)

    def is_blocked(self, method: str, url: str) -> bool:
        return endpoint_key(method, url) in self.endpoint_blocked

    def _strike(self, key: str, response: Response) -> None:
        if response.blocked:
            self.endpoint_strikes[key] = self.endpoint_strikes.get(key, 0) + 1
            if self.endpoint_strikes[key] >= 3:
                self.endpoint_blocked.add(key)
                self._log("info", "3-strikes em %s", key)
        elif response.status and response.status < 500:
            self.endpoint_strikes[key] = 0

    # ----------------------------------------------------------------- request
    def request(
        self,
        method: str,
        url: str,
        headers: dict | None = None,
        data: str | bytes | None = None,
        json_body: dict | list | None = None,
        follow_redirects: bool = True,
        candidate_id: str = "",
    ) -> Response:
        method = method.upper()
        ok, normalized, reason = self.scope.normalize(url)
        if not ok:
            self._out_of_scope(url, reason)
            raise ScopeViolation(url, reason)
        url = normalized
        key = endpoint_key(method, url)
        if key in self.endpoint_blocked:
            raise BudgetExceeded(f"endpoint bloqueado (3-strikes): {key}")
        if self.endpoint_counts.get(key, 0) >= MAX_PER_ENDPOINT:
            raise BudgetExceeded(f"teto de {MAX_PER_ENDPOINT} requisições por endpoint: {key}")

        request_headers = {"User-Agent": "triager/1.0 (authorised, non-destructive)"}
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

        response: Response | None = None
        # limite: MAX_ATTEMPTS (2) tentativas por requisição.
        for attempt in range(MAX_ATTEMPTS):
            self.budget.check_target()
            self.budget.wait_rate(urlsplit(url).hostname or self.scope.host)
            self.budget.consume_request(self.phase, candidate_id or self.candidate_id, self.scope.host)
            self.endpoint_counts[key] = self.endpoint_counts.get(key, 0) + 1
            started = time.monotonic()
            try:
                response = self._send(method, url, request_headers, payload)
            except Exception as exc:
                response = Response(method=method, url=url, status=0, error=f"{type(exc).__name__}: {exc}")
            response.elapsed = time.monotonic() - started
            response.request_headers = dict(request_headers)
            response.request_body = body_text
            if attempt == 0 and response.status in (429, 500, 502, 503, 504):
                time.sleep(1.0)
                continue
            break

        assert response is not None
        self._strike(key, response)
        if follow_redirects and response.status in (301, 302, 303, 307, 308):
            location = response.headers.get("location", "")
            if location:
                target = urljoin(url, location)
                allowed, _normalized, why = self.scope.normalize(target)
                if not allowed:
                    response.redirect_external = target
                    self._out_of_scope(target, f"redirect externo: {why}")
                    self._log("info", "redirect externo registrado: %s", target)
                else:
                    followed = self.request("GET", target, headers=headers, follow_redirects=False, candidate_id=candidate_id)
                    return followed
        self._log("info", "%s %s -> %s (%.3fs)", method, url, response.status, response.elapsed)
        return response

    def get(self, url: str, **kwargs) -> Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> Response:
        return self.request("POST", url, **kwargs)

    # --------------------------------------------------------------- transport
    def _send(self, method: str, url: str, headers: dict, payload) -> Response:
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
                )
            except Exception as exc:
                return Response(method=method, url=url, status=0, error=f"{type(exc).__name__}: {exc}")
        return self._send_urllib(method, url, headers, payload)

    def _send_urllib(self, method: str, url: str, headers: dict, payload) -> Response:  # pragma: no cover
        import urllib.error
        import urllib.request

        request = urllib.request.Request(url, data=payload, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=READ_TIMEOUT) as raw:
                body = raw.read(1_000_000)
                return Response(
                    method=method,
                    url=url,
                    status=getattr(raw, "status", raw.getcode()),
                    headers={k.lower(): v for k, v in raw.headers.items()},
                    text=body.decode("utf-8", "replace"),
                )
        except urllib.error.HTTPError as exc:
            body = exc.read(1_000_000) if hasattr(exc, "read") else b""
            return Response(
                method=method,
                url=url,
                status=exc.code,
                headers={k.lower(): v for k, v in exc.headers.items()} if exc.headers else {},
                text=body.decode("utf-8", "replace"),
            )
        except Exception as exc:
            return Response(method=method, url=url, status=0, error=f"{type(exc).__name__}: {exc}")
