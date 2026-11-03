"""Real client address behind an authenticated edge proxy.

Hosted dashboards sit behind two proxies: Cloudflare, then the platform router on
Fly. Fly rewrites ``X-Forwarded-For`` into ``<client>, <Cloudflare edge>, <app IP>``
and the dashboard's peer is Fly's own proxy, so the uvicorn trusted-proxy walk
(``dashboard.trusted_proxies``) cannot recover the browser's address without
trusting every Cloudflare range plus the platform's addresses. Cloudflare also
sends the address directly, as ``CF-Connecting-IP``, but any caller that reaches
the origin without Cloudflare can type that header.

So the edge proves itself first: Cloudflare adds a secret header to every request
it forwards (the same origin lock the platform router enforces), and only a
request carrying that secret may rewrite ``scope["client"]`` from the client-IP
header. Everything downstream (``client_ip`` in request_utils: the password
throttle, native pending caps, the auth audit log) then keys on the browser's
address. A request without the secret keeps whatever uvicorn resolved.

Env-provisioned like the drain secret, never from ``config.yaml``:

  HERMES_DASHBOARD_EDGE_AUTH_SECRET      comma-separated accepted values (two during a rotation);
                                         unset = middleware inactive
  HERMES_DASHBOARD_EDGE_AUTH_HEADER      default ``x-nous-edge-auth``
  HERMES_DASHBOARD_EDGE_CLIENT_IP_HEADER default ``cf-connecting-ip``
"""
from __future__ import annotations

import hmac
import ipaddress
import logging
import os
from typing import Mapping, Optional

from starlette.types import ASGIApp, Receive, Scope, Send

_log = logging.getLogger(__name__)

ENV_SECRET = "HERMES_DASHBOARD_EDGE_AUTH_SECRET"
ENV_AUTH_HEADER = "HERMES_DASHBOARD_EDGE_AUTH_HEADER"
ENV_CLIENT_IP_HEADER = "HERMES_DASHBOARD_EDGE_CLIENT_IP_HEADER"
DEFAULT_AUTH_HEADER = "x-nous-edge-auth"
DEFAULT_CLIENT_IP_HEADER = "cf-connecting-ip"
# 32 chars is the floor the platform router applies to its own shared secrets.
MIN_SECRET_CHARS = 32


def edge_client_ip_options(environ: Optional[Mapping[str, str]] = None) -> Optional[dict]:
    """Keyword arguments for ``EdgeClientIpMiddleware`` from the env, or ``None`` when
    ``HERMES_DASHBOARD_EDGE_AUTH_SECRET`` is unset (middleware inactive).

    Short values are refused (and logged) rather than accepted: a guessable secret would let
    anyone pick their own rate-limit bucket, which is worse than the proxy-address bucket.
    """
    env = os.environ if environ is None else environ
    raw = env.get(ENV_SECRET, "")
    if not raw.strip():
        return None
    secrets: list[bytes] = []
    for value in raw.split(","):
        value = value.strip()
        if not value:
            continue
        if len(value) < MIN_SECRET_CHARS:
            _log.warning("%s: ignoring a value shorter than %d characters", ENV_SECRET, MIN_SECRET_CHARS)
            continue
        secrets.append(value.encode("utf-8"))
    if not secrets:
        _log.warning("%s is set but holds no usable value; client addresses stay as the proxy reports them",
                     ENV_SECRET)
        return None
    auth_header = (env.get(ENV_AUTH_HEADER, "").strip() or DEFAULT_AUTH_HEADER).lower()
    client_ip_header = (env.get(ENV_CLIENT_IP_HEADER, "").strip() or DEFAULT_CLIENT_IP_HEADER).lower()
    _log.info("Dashboard client addresses: %s when %s carries the edge secret", client_ip_header, auth_header)
    return {"secrets": tuple(secrets), "auth_header": auth_header, "client_ip_header": client_ip_header}


class EdgeClientIpMiddleware:
    """Rewrite ``scope["client"]`` from the edge's client-IP header when the edge-auth header
    matches one of the accepted secrets. Pure ASGI: covers HTTP and WebSocket scopes."""

    def __init__(self, app: ASGIApp, *, secrets: tuple[bytes, ...],
                 auth_header: str = DEFAULT_AUTH_HEADER,
                 client_ip_header: str = DEFAULT_CLIENT_IP_HEADER) -> None:
        if not secrets:
            raise ValueError("EdgeClientIpMiddleware needs at least one secret")
        self.app = app
        self._secrets = secrets
        self._auth_header = auth_header.strip().lower().encode("latin1")
        self._client_ip_header = client_ip_header.strip().lower().encode("latin1")

    def edge_client(self, headers: list[tuple[bytes, bytes]]) -> Optional[str]:
        """The client address the edge vouches for, or ``None`` when the request is not verified.

        Exactly one auth header value, compared in constant time against each accepted secret, and
        exactly one client-IP header holding a parseable address; a repeated header is as wrong as
        a bad one, so a caller cannot smuggle a second value past a proxy that keeps the first.
        """
        auth = [value for name, value in headers if name == self._auth_header]
        if len(auth) != 1 or not any(hmac.compare_digest(auth[0], secret) for secret in self._secrets):
            return None
        addresses = [value for name, value in headers if name == self._client_ip_header]
        if len(addresses) != 1:
            return None
        try:
            return str(ipaddress.ip_address(addresses[0].decode("latin1").strip()))
        except (UnicodeDecodeError, ValueError):
            return None

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] in ("http", "websocket"):
            client = self.edge_client(scope.get("headers") or [])
            if client is not None:
                # Port is unknowable past two proxies; uvicorn's own proxy middleware reports 0 too.
                scope["client"] = (client, 0)
        await self.app(scope, receive, send)
