"""Real client address behind an edge proxy that fronts a platform proxy.

Hosted dashboards sit behind two proxies: Cloudflare, then the platform router on
Fly. Fly rewrites ``X-Forwarded-For`` into ``<client>, <Cloudflare edge>, <app IP>``
and the dashboard's peer is Fly's own proxy, so the uvicorn trusted-proxy walk
(``dashboard.trusted_proxies``) cannot recover the browser's address without
trusting every Cloudflare range plus the platform's addresses. Cloudflare also
sends the address directly, as ``CF-Connecting-IP``, but any caller that reaches
the origin without Cloudflare can type that header.

So the request must first prove it came through the edge. Fly's edge sets
``Fly-Client-IP`` to the address that connected to it (a client cannot supply it,
and the platform router forwards it unchanged); for traffic that came through
Cloudflare that is a Cloudflare edge address, inside Cloudflare's published
ranges. Only then is ``scope["client"]`` rewritten from the client-IP header, and
everything downstream (``client_ip`` in request_utils: the password throttle,
native pending caps, the auth audit log) keys on the browser's address. A request
whose edge address is outside the ranges keeps whatever uvicorn resolved. No
secret is involved, so nothing here is worth stealing from an agent's traffic.

Env-provisioned (the platform knows which edge fronts it; ``config.yaml`` does not):

  HERMES_DASHBOARD_EDGE_IP_RANGES        comma-separated CIDRs the edge connects from, or the
                                         alias ``cloudflare`` for Cloudflare's published ranges;
                                         unset = middleware inactive
  HERMES_DASHBOARD_EDGE_IP_HEADER        default ``fly-client-ip``: the address that reached the
                                         platform's edge
  HERMES_DASHBOARD_EDGE_CLIENT_IP_HEADER default ``cf-connecting-ip``: the browser, as the edge says
"""
from __future__ import annotations

import ipaddress
import logging
import os
from typing import Mapping, Optional

from starlette.types import ASGIApp, Receive, Scope, Send

_log = logging.getLogger(__name__)

ENV_RANGES = "HERMES_DASHBOARD_EDGE_IP_RANGES"
ENV_EDGE_IP_HEADER = "HERMES_DASHBOARD_EDGE_IP_HEADER"
ENV_CLIENT_IP_HEADER = "HERMES_DASHBOARD_EDGE_CLIENT_IP_HEADER"
DEFAULT_EDGE_IP_HEADER = "fly-client-ip"
DEFAULT_CLIENT_IP_HEADER = "cf-connecting-ip"

# https://www.cloudflare.com/ips-v4/ and /ips-v6/ as of 2026-11-03. Cloudflare adds a
# range a few times a year; the alias is a convenience, explicit CIDRs always win.
CLOUDFLARE_RANGES: tuple[str, ...] = (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
    "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
)
RANGE_ALIASES: dict[str, tuple[str, ...]] = {"cloudflare": CLOUDFLARE_RANGES}

_Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def parse_edge_ranges(raw: str) -> list[_Network]:
    """Bounded networks from a comma-separated list of CIDRs and aliases.

    Unbounded (``/0``) and malformed entries are dropped with a warning rather than widening
    trust: an edge range that admits everyone would let any caller choose its own address.
    """
    networks: list[_Network] = []
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        for cidr in RANGE_ALIASES.get(entry.lower(), (entry,)):
            try:
                network = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                _log.warning("%s: ignoring %r; expected a CIDR network or one of %s",
                             ENV_RANGES, entry, ", ".join(sorted(RANGE_ALIASES)))
                break
            if network.prefixlen == 0:
                _log.warning("%s: ignoring unbounded network %r", ENV_RANGES, entry)
                continue
            if network not in networks:
                networks.append(network)
    return networks


def edge_client_ip_options(environ: Optional[Mapping[str, str]] = None) -> Optional[dict]:
    """Keyword arguments for ``EdgeClientIpMiddleware`` from the env, or ``None`` when
    ``HERMES_DASHBOARD_EDGE_IP_RANGES`` is unset or holds no usable network (inactive)."""
    env = os.environ if environ is None else environ
    raw = env.get(ENV_RANGES, "")
    if not raw.strip():
        return None
    networks = parse_edge_ranges(raw)
    if not networks:
        _log.warning("%s is set but holds no usable network; client addresses stay as the proxy reports them",
                     ENV_RANGES)
        return None
    edge_ip_header = (env.get(ENV_EDGE_IP_HEADER, "").strip() or DEFAULT_EDGE_IP_HEADER).lower()
    client_ip_header = (env.get(ENV_CLIENT_IP_HEADER, "").strip() or DEFAULT_CLIENT_IP_HEADER).lower()
    _log.info("Dashboard client addresses: %s when %s is inside %d edge network(s)",
              client_ip_header, edge_ip_header, len(networks))
    return {"edge_networks": tuple(networks), "edge_ip_header": edge_ip_header,
            "client_ip_header": client_ip_header}


class EdgeClientIpMiddleware:
    """Rewrite ``scope["client"]`` from the edge's client-IP header when the edge-IP header holds
    an address inside the trusted edge networks. Pure ASGI: covers HTTP and WebSocket scopes."""

    def __init__(self, app: ASGIApp, *, edge_networks: tuple[_Network, ...],
                 edge_ip_header: str = DEFAULT_EDGE_IP_HEADER,
                 client_ip_header: str = DEFAULT_CLIENT_IP_HEADER) -> None:
        if not edge_networks:
            raise ValueError("EdgeClientIpMiddleware needs at least one edge network")
        self.app = app
        self._edge_networks = edge_networks
        self._edge_ip_header = edge_ip_header.strip().lower().encode("latin1")
        self._client_ip_header = client_ip_header.strip().lower().encode("latin1")

    @staticmethod
    def _single_address(headers: list[tuple[bytes, bytes]], name: bytes):
        """The one parseable address under ``name``, or ``None``. Exactly one value: a repeated
        header is how a caller smuggles a second value past a proxy that keeps the first."""
        values = [value for key, value in headers if key == name]
        if len(values) != 1:
            return None
        try:
            return ipaddress.ip_address(values[0].decode("latin1").strip())
        except (UnicodeDecodeError, ValueError):
            return None

    def edge_client(self, headers: list[tuple[bytes, bytes]]) -> Optional[str]:
        """The client address the edge vouches for, or ``None`` when the request did not come
        through a trusted edge address."""
        edge = self._single_address(headers, self._edge_ip_header)
        if edge is None:
            return None
        if isinstance(edge, ipaddress.IPv6Address) and edge.ipv4_mapped is not None:
            edge = edge.ipv4_mapped
        if not any(edge in network for network in self._edge_networks):
            return None
        client = self._single_address(headers, self._client_ip_header)
        return None if client is None else str(client)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] in ("http", "websocket"):
            client = self.edge_client(scope.get("headers") or [])
            if client is not None:
                # Port is unknowable past two proxies; uvicorn's own proxy middleware reports 0 too.
                scope["client"] = (client, 0)
        await self.app(scope, receive, send)
