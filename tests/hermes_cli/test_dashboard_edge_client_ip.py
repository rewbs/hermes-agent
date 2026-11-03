"""Edge-verified client address (dashboard_auth/edge_client_ip.py)."""
from __future__ import annotations

import logging
from typing import Any, cast

import pytest
from starlette.testclient import TestClient

from hermes_cli.dashboard_auth.edge_client_ip import (
    DEFAULT_CLIENT_IP_HEADER, DEFAULT_EDGE_IP_HEADER, ENV_CLIENT_IP_HEADER, ENV_EDGE_IP_HEADER, ENV_RANGES,
    EdgeClientIpMiddleware, edge_client_ip_options, parse_edge_ranges)

PEER = ("fdaa:0:1:a7b::2", 40000)


def _echo_client_app(seen: list):
    async def app(scope, receive, send):
        seen.append((scope["type"], scope.get("client")))
        if scope["type"] == "websocket":
            await send({"type": "websocket.close"})
            return
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})
    return app


def _client(middleware) -> TestClient:
    return TestClient(cast(Any, middleware), client=PEER)


@pytest.fixture
def middleware_and_seen():
    seen: list = []
    networks = tuple(parse_edge_ranges("198.51.100.0/24, 2001:db8::/32"))
    return EdgeClientIpMiddleware(_echo_client_app(seen), edge_networks=networks), seen


def test_request_from_the_edge_adopts_client_ip(middleware_and_seen):
    middleware, seen = middleware_and_seen
    _client(middleware).get("/", headers={DEFAULT_EDGE_IP_HEADER: "198.51.100.7",
                                          DEFAULT_CLIENT_IP_HEADER: "203.0.113.9"})
    assert seen == [("http", ("203.0.113.9", 0))]


@pytest.mark.parametrize("edge", ["2001:db8:1::9", "::ffff:198.51.100.8"], ids=["v6", "v4-mapped"])
def test_edge_address_forms(middleware_and_seen, edge):
    middleware, seen = middleware_and_seen
    _client(middleware).get("/", headers={DEFAULT_EDGE_IP_HEADER: edge, DEFAULT_CLIENT_IP_HEADER: "2001:db8::9"})
    assert seen == [("http", ("2001:db8::9", 0))]


@pytest.mark.parametrize(
    "headers",
    [
        pytest.param({DEFAULT_CLIENT_IP_HEADER: "203.0.113.9"}, id="no-edge-header"),
        pytest.param({DEFAULT_EDGE_IP_HEADER: "203.0.113.1", DEFAULT_CLIENT_IP_HEADER: "203.0.113.9"},
                     id="edge-outside-ranges"),
        pytest.param({DEFAULT_EDGE_IP_HEADER: "not-an-ip", DEFAULT_CLIENT_IP_HEADER: "203.0.113.9"},
                     id="bad-edge-ip"),
        pytest.param({DEFAULT_EDGE_IP_HEADER: "198.51.100.7"}, id="no-client-ip"),
        pytest.param({DEFAULT_EDGE_IP_HEADER: "198.51.100.7", DEFAULT_CLIENT_IP_HEADER: "not-an-ip"},
                     id="bad-client-ip"),
        pytest.param({DEFAULT_EDGE_IP_HEADER: "198.51.100.7", DEFAULT_CLIENT_IP_HEADER: "203.0.113.9, 198.51.100.1"},
                     id="client-ip-list"),
    ],
)
def test_unverified_request_keeps_peer_address(middleware_and_seen, headers):
    middleware, seen = middleware_and_seen
    _client(middleware).get("/", headers=headers)
    assert seen == [("http", PEER)]


def test_repeated_headers_are_not_trusted(middleware_and_seen):
    middleware, seen = middleware_and_seen
    client = _client(middleware)
    client.get("/", headers=[(DEFAULT_EDGE_IP_HEADER, "198.51.100.7"), (DEFAULT_EDGE_IP_HEADER, "198.51.100.7"),
                             (DEFAULT_CLIENT_IP_HEADER, "203.0.113.9")])
    client.get("/", headers=[(DEFAULT_EDGE_IP_HEADER, "198.51.100.7"), (DEFAULT_CLIENT_IP_HEADER, "203.0.113.9"),
                             (DEFAULT_CLIENT_IP_HEADER, "198.51.100.1")])
    assert seen == [("http", PEER)] * 2


def test_websocket_scope_is_rewritten_too(middleware_and_seen):
    middleware, seen = middleware_and_seen
    with pytest.raises(Exception):  # the echo app closes the socket without accepting
        with _client(middleware).websocket_connect(
                "/ws", headers={DEFAULT_EDGE_IP_HEADER: "198.51.100.7", DEFAULT_CLIENT_IP_HEADER: "203.0.113.9"}):
            pass
    assert seen == [("websocket", ("203.0.113.9", 0))]


def test_cloudflare_alias_covers_published_ranges():
    networks = parse_edge_ranges("cloudflare")
    assert len(networks) == 22
    import ipaddress
    for ip in ("104.16.0.1", "172.71.9.9", "2606:4700::1"):
        assert any(ipaddress.ip_address(ip) in n for n in networks), ip
    for ip in ("37.16.5.185", "8.8.8.8", "2a09:8280:1::1"):
        assert not any(ipaddress.ip_address(ip) in n for n in networks), ip


def test_parse_drops_unbounded_and_malformed_entries(caplog):
    with caplog.at_level(logging.WARNING):
        networks = parse_edge_ranges("0.0.0.0/0, ::/0, nope, 198.51.100.7, 198.51.100.0/24")
    assert [str(n) for n in networks] == ["198.51.100.7/32", "198.51.100.0/24"]
    assert "unbounded network '0.0.0.0/0'" in caplog.text
    assert "ignoring 'nope'" in caplog.text


def test_options_absent_without_ranges(caplog):
    assert edge_client_ip_options({}) is None
    assert edge_client_ip_options({ENV_RANGES: "   "}) is None
    assert caplog.text == ""


def test_options_absent_when_nothing_usable(caplog):
    with caplog.at_level(logging.WARNING):
        assert edge_client_ip_options({ENV_RANGES: "::/0"}) is None
    assert "holds no usable network" in caplog.text


def test_options_parse_alias_and_header_overrides():
    options = edge_client_ip_options({
        ENV_RANGES: "cloudflare, 198.51.100.0/24",
        ENV_EDGE_IP_HEADER: "X-Edge-Peer",
        ENV_CLIENT_IP_HEADER: "True-Client-IP",
    })
    assert options is not None
    assert len(options["edge_networks"]) == 23
    assert options["edge_ip_header"] == "x-edge-peer"
    assert options["client_ip_header"] == "true-client-ip"
    seen: list = []
    middleware = EdgeClientIpMiddleware(_echo_client_app(seen), **options)
    _client(middleware).get("/", headers={"X-Edge-Peer": "104.16.0.1", "True-Client-IP": "203.0.113.9"})
    assert seen == [("http", ("203.0.113.9", 0))]
