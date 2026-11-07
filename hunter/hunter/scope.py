"""Target parsing and strict scope enforcement.

All HTTP traffic passes through :class:`Scope` before it is sent.  Anything
whose hostname is not *exactly* one of the operator supplied target hosts is
recorded and never requested.
"""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass
from urllib.parse import urlsplit

DEFAULT_PORTS = {"http": 80, "https": 443}


class ScopeError(ValueError):
    pass


def _env_default_scheme() -> str:
    return os.environ.get("HUNTER_DEFAULT_SCHEME", "https").lower()


def _env_default_port() -> int | None:
    raw = os.environ.get("HUNTER_DEFAULT_PORT", "")
    if raw.isdigit():
        return int(raw)
    return None


@dataclass(frozen=True)
class Target:
    host: str
    port: int
    scheme: str
    original: str
    url: str

    @property
    def netloc(self) -> str:
        default = DEFAULT_PORTS.get(self.scheme)
        if self.port == default:
            return self.host
        return f"{self.host}:{self.port}"


def _clean_host(host: str) -> str:
    host = host.strip().rstrip(".").lower()
    if not host:
        raise ScopeError("host vazio")
    if any(ch.isspace() for ch in host):
        raise ScopeError("host contém espaços")
    # Homoglyphs / non-ascii hostnames are never tested.
    try:
        host.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ScopeError("host não-ASCII (homóglifo) não suportado") from exc
    return host


def parse_target(raw: str) -> Target:
    raw = (raw or "").strip()
    if not raw:
        raise ScopeError("alvo vazio")
    candidate = raw if "://" in raw else f"{_env_default_scheme()}://{raw}"
    parts = urlsplit(candidate)
    if parts.scheme not in ("http", "https"):
        raise ScopeError(f"esquema não suportado: {parts.scheme}")
    if parts.username or parts.password:
        raise ScopeError("credenciais embutidas no alvo não são permitidas")
    if not parts.hostname:
        raise ScopeError("alvo sem host")
    host = _clean_host(parts.hostname)
    port = parts.port or _env_default_port() or DEFAULT_PORTS[parts.scheme]
    # A path/query in a target is ignored for scope purposes: only the origin
    # is tested, and the origin is the exact host that was supplied.
    default = DEFAULT_PORTS[parts.scheme]
    netloc = host if port == default else f"{host}:{port}"
    return Target(host=host, port=port, scheme=parts.scheme, original=raw, url=f"{parts.scheme}://{netloc}")


class Scope:
    """Allowlist for a single target host and port."""

    def __init__(self, target: Target):
        self.target = target
        self.host = target.host
        self.port = target.port
        self.scheme = target.scheme

    @property
    def url(self) -> str:
        return self.target.url

    def check(self, url: str) -> tuple[bool, str]:
        """Return (allowed, reason).  Never performs I/O."""
        try:
            parts = urlsplit(url)
        except ValueError:
            return False, "URL inválida"
        if parts.scheme not in ("http", "https"):
            return False, f"esquema fora de escopo ({parts.scheme or '?'})"
        if parts.username or parts.password:
            return False, "credenciais na URL"
        try:
            host = _clean_host(parts.hostname or "")
            port = parts.port or DEFAULT_PORTS[parts.scheme]
        except (ScopeError, ValueError):
            return False, "host de destino inválido"
        if host != self.host:
            return False, f"host externo ({host})"
        if port != self.port:
            return False, f"porta fora de escopo ({port})"
        return True, ""

    def url_for(self, path: str) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            return path
        if not path.startswith("/"):
            path = "/" + path
        return self.target.url + path

    @staticmethod
    def looks_like_ip(host: str) -> bool:
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False
