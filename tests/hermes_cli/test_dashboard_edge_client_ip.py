"""Edge-authenticated client address (dashboard_auth/edge_client_ip.py)."""
from __future__ import annotations

import logging
from typing import Any, cast

import pytest
from starlette.testclient import TestClient

from hermes_cli.dashboard_auth.edge_client_ip import (
    DEFAULT_AUTH_HEADER, DEFAULT_CLIENT_IP_HEADER, ENV_AUTH_HEADER, ENV_CLIENT_IP_HEADER, ENV_SECRET,
    EdgeClientIpMiddleware, edge_client_ip_options)

SECRET = "0123456789abcdef0123456789abcdef"
SECRET_NEXT = "fedcba9876543210fedcba9876543210"


def _echo_client_app(seen: list):
    async def app(scope, receive, send):
        seen.append((scope["type"], scope.get("client")))
        if scope["type"] == "websocket":
            await send({"type": "websocket.close"})
            return
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})
    return app


def _client(middleware, peer: str = "fdaa:0:1:a7b::2") -> TestClient:
    return TestClient(cast(Any, middleware), client=(peer, 40000))


@pytest.fixture
def middleware_and_seen():
    seen: list = []
    middleware = EdgeClientIpMiddleware(_echo_client_app(seen), secrets=(SECRET.encode(), SECRET_NEXT.encode()))
    return middleware, seen


def test_verified_request_adopts_edge_client_ip(middleware_and_seen):
    middleware, seen = middleware_and_seen
    _client(middleware).get("/", headers={DEFAULT_AUTH_HEADER: SECRET, DEFAULT_CLIENT_IP_HEADER: "203.0.113.9"})
    assert seen == [("http", ("203.0.113.9", 0))]


def test_secondary_secret_is_accepted_during_rotation(middleware_and_seen):
    middleware, seen = middleware_and_seen
    _client(middleware).get("/", headers={DEFAULT_AUTH_HEADER: SECRET_NEXT, DEFAULT_CLIENT_IP_HEADER: "2001:db8::9"})
    assert seen == [("http", ("2001:db8::9", 0))]


@pytest.mark.parametrize(
    "headers",
    [
        pytest.param({DEFAULT_CLIENT_IP_HEADER: "203.0.113.9"}, id="no-auth-header"),
        pytest.param({DEFAULT_AUTH_HEADER: "wrong", DEFAULT_CLIENT_IP_HEADER: "203.0.113.9"}, id="wrong-secret"),
        pytest.param({DEFAULT_AUTH_HEADER: SECRET}, id="no-client-ip"),
        pytest.param({DEFAULT_AUTH_HEADER: SECRET, DEFAULT_CLIENT_IP_HEADER: "not-an-ip"}, id="bad-client-ip"),
        pytest.param({DEFAULT_AUTH_HEADER: SECRET, DEFAULT_CLIENT_IP_HEADER: "203.0.113.9, 198.51.100.1"},
                     id="client-ip-list"),
    ],
)
def test_unverified_request_keeps_peer_address(middleware_and_seen, headers):
    middleware, seen = middleware_and_seen
    _client(middleware).get("/", headers=headers)
    assert seen == [("http", ("fdaa:0:1:a7b::2", 40000))]


def test_repeated_headers_are_not_trusted(middleware_and_seen):
    # A second value is how a caller smuggles its own address past a proxy that
    # keeps the first; exactly one of each header is required.
    middleware, seen = middleware_and_seen
    client = _client(middleware)
    client.get("/", headers=[(DEFAULT_AUTH_HEADER, SECRET), (DEFAULT_AUTH_HEADER, SECRET),
                             (DEFAULT_CLIENT_IP_HEADER, "203.0.113.9")])
    client.get("/", headers=[(DEFAULT_AUTH_HEADER, SECRET), (DEFAULT_CLIENT_IP_HEADER, "203.0.113.9"),
                             (DEFAULT_CLIENT_IP_HEADER, "198.51.100.1")])
    assert seen == [("http", ("fdaa:0:1:a7b::2", 40000))] * 2


def test_websocket_scope_is_rewritten_too(middleware_and_seen):
    middleware, seen = middleware_and_seen
    with pytest.raises(Exception):  # the echo app closes the socket without accepting
        with _client(middleware).websocket_connect(
                "/ws", headers={DEFAULT_AUTH_HEADER: SECRET, DEFAULT_CLIENT_IP_HEADER: "203.0.113.9"}):
            pass
    assert seen == [("websocket", ("203.0.113.9", 0))]


def test_options_absent_without_secret(caplog):
    assert edge_client_ip_options({}) is None
    assert edge_client_ip_options({ENV_SECRET: "   "}) is None
    assert caplog.text == ""


def test_options_refuse_short_secrets(caplog):
    with caplog.at_level(logging.WARNING):
        assert edge_client_ip_options({ENV_SECRET: "short"}) is None
    assert "shorter than 32 characters" in caplog.text


def test_options_parse_rotation_list_and_header_overrides():
    options = edge_client_ip_options({
        ENV_SECRET: f" {SECRET}, {SECRET_NEXT},short, ",
        ENV_AUTH_HEADER: "X-Edge-Proof",
        ENV_CLIENT_IP_HEADER: "True-Client-IP",
    })
    assert options == {
        "secrets": (SECRET.encode(), SECRET_NEXT.encode()),
        "auth_header": "x-edge-proof",
        "client_ip_header": "true-client-ip",
    }
    seen: list = []
    middleware = EdgeClientIpMiddleware(_echo_client_app(seen), **options)
    _client(middleware).get("/", headers={"X-Edge-Proof": SECRET, "True-Client-IP": "203.0.113.9"})
    assert seen == [("http", ("203.0.113.9", 0))]
