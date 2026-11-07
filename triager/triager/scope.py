"""Host normalisation, allowlist and scope enforcement.

Every URL that comes from a scan output is untrusted.  It is normalised here and
only ever requested after passing :meth:`Scope.check`.
"""

from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

DEFAULT_PORTS = {"http": 80, "https": 443}
MAX_URL_LEN = 2048
HOST_RE = re.compile(r"^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$")


class ScopeError(ValueError):
    pass


def _default_scheme() -> str:
    return os.environ.get("TRIAGER_DEFAULT_SCHEME", "https").lower()


def _default_port() -> int | None:
    raw = os.environ.get("TRIAGER_DEFAULT_PORT", "")
    return int(raw) if raw.isdigit() else None


def normalize_host(host: str) -> str:
    host = (host or "").strip().rstrip(".").lower()
    if not host:
        raise ScopeError("host vazio")
    if any(ch.isspace() for ch in host):
        raise ScopeError("host contém espaços")
    try:
        host.encode("ascii")
    except UnicodeEncodeError as exc:  # homoglyph / IDNA trick
        raise ScopeError("host não-ASCII (homóglifo) rejeitado") from exc
    if ":" in host:  # IPv6 literal without brackets, keep as-is but normalised below
        try:
            return str(ipaddress.ip_address(host))
        except ValueError as exc:
            raise ScopeError("host inválido") from exc
    if not HOST_RE.match(host):
        raise ScopeError(f"host inválido: {host}")
    return host


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def is_private_host(host: str) -> bool:
    host = host.lower()
    if host in ("localhost", "localhost.localdomain") or host.endswith(".localhost"):
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast
    except ValueError:
        return host.endswith(".local") or host.endswith(".internal")


@dataclass(frozen=True)
class Target:
    host: str
    port: int
    scheme: str
    original: str

    @property
    def url(self) -> str:
        default = DEFAULT_PORTS[self.scheme]
        netloc = self.host if self.port == default else f"{self.host}:{self.port}"
        return f"{self.scheme}://{netloc}"


def parse_target(raw: str) -> Target:
    raw = (raw or "").strip()
    if not raw:
        raise ScopeError("alvo vazio")
    candidate = raw if "://" in raw else f"{_default_scheme()}://{raw}"
    parts = urlsplit(candidate)
    if parts.scheme not in ("http", "https"):
        raise ScopeError(f"esquema não suportado: {parts.scheme}")
    if parts.username or parts.password:
        raise ScopeError("credenciais embutidas não permitidas")
    if not parts.hostname:
        raise ScopeError("alvo sem host")
    host = normalize_host(parts.hostname)
    port = parts.port or _default_port() or DEFAULT_PORTS[parts.scheme]
    return Target(host=host, port=port, scheme=parts.scheme, original=raw)


class Scope:
    """Allowlist for one authorised target."""

    def __init__(self, target: Target, allow_private: bool = False):
        self.target = target
        self.host = target.host
        self.port = target.port
        self.scheme = target.scheme
        self.allow_private = allow_private

    @property
    def url(self) -> str:
        return self.target.url

    def normalize(self, url: str) -> tuple[bool, str, str]:
        """Return (ok, normalized_url_or_reason, reason_when_bad)."""
        url = (url or "").strip()
        if not url:
            return False, "", "URL vazia"
        if len(url) > MAX_URL_LEN:
            return False, "", "URL acima do limite de 2048 chars"
        if "://" not in url:
            url = f"{self.scheme}://{self.host}" + (url if url.startswith("/") else "/" + url)
        try:
            parts = urlsplit(url)
        except ValueError:
            return False, "", "URL inválida"
        if parts.scheme not in ("http", "https"):
            return False, "", f"esquema fora de escopo ({parts.scheme or '?'})"
        if parts.username or parts.password:
            return False, "", "userinfo na URL bloqueado"
        try:
            host = normalize_host(parts.hostname or "")
            port = parts.port or DEFAULT_PORTS[parts.scheme]
        except (ScopeError, ValueError) as exc:
            return False, "", f"host inválido ({exc})"
        if is_private_host(host) and not self.allow_private:
            return False, "", "host privado/loopback bloqueado (use --allow-private)"
        if host != self.host:
            return False, "", f"host externo ({host})"
        if port != self.port:
            return False, "", f"porta fora de escopo ({port})"
        default = DEFAULT_PORTS[parts.scheme]
        netloc = host if port == default else f"{host}:{port}"
        normalized = parts._replace(scheme=parts.scheme.lower(), netloc=netloc).geturl()
        return True, normalized, ""

    def check(self, url: str) -> tuple[bool, str]:
        ok, _normalized, reason = self.normalize(url)
        return ok, reason

    def url_for(self, path: str) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            return path
        return self.target.url + (path if path.startswith("/") else "/" + path)


def load_targets(values: str | None, file_path: str | None, allow_private: bool) -> list[Scope]:
    raw_targets: list[str] = []
    for item in (values or "").split(","):
        item = item.strip()
        if item:
            raw_targets.append(item)
    if file_path:
        try:
            with open(file_path, "r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        raw_targets.append(line)
        except OSError as exc:
            raise ScopeError(f"não foi possível ler --targets-file: {exc}") from exc
    scopes: list[Scope] = []
    seen = set()
    for raw in raw_targets:
        target = parse_target(raw)
        key = (target.host, target.port)
        if key in seen:
            continue
        seen.add(key)
        scopes.append(Scope(target, allow_private=allow_private))
    return scopes
