#!/usr/bin/env python3
"""The private Admin gateway's authorization check, outside the MCP server.

Run:
    python3 mcp/admin_gateway.py
    python3 mcp/admin_gateway.py --check

nginx's `auth_request` asks one question per Admin request: does the bearer token in
this request permit exactly this method, normalized path and query?  The answer has to
come from somewhere the constrained process cannot rewrite, so it is served here — its
own container, its own user, one route, no tool registry, no Cedar PDP, no Admin client
and no Workload API credentials.  It can verify a signature against Keycloak's JWKS and
nothing else, which means compromising it cannot produce a token the gateway accepts.

Nothing is trusted from the request except the four headers nginx sets, and a request
the checker cannot understand is a denial (403), never a fallback.  It binds loopback
only; the private Admin listener is the only thing that talks to it.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from collections.abc import Mapping

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route

from auth import KeycloakAuthConfig, TokenError, bearer_from_header
from delegation import (
    ADMIN_CHECK_PATH,
    ADMIN_CHECK_PORT,
    DelegatedAdmin,
    DelegationConfig,
    DelegationError,
    gateway_capability,
)

ALLOW = 204
DENY = 403
PORT_ENV = "KC_MCP_ADMIN_CHECK_PORT"


async def check(
    delegate: DelegatedAdmin, method: str, path: str, query: str, authorization: str | None
) -> int:
    """Return the status the gateway should act on: 204 for this exact request, else 403."""
    capability = gateway_capability(delegate.config.admin_path, method, path, query)
    if capability is None:
        return DENY
    try:
        await delegate.verify_token(bearer_from_header(authorization), capability)
    except (TokenError, DelegationError):
        return DENY
    return ALLOW


def build_app(delegate: DelegatedAdmin) -> Starlette:
    async def admin_check(request: Request) -> Response:
        try:
            status = await check(
                delegate,
                request.headers.get("x-admin-method", ""),
                request.headers.get("x-admin-path", ""),
                request.headers.get("x-admin-query", ""),
                request.headers.get("authorization"),
            )
        except Exception as exc:  # an unreadable request denies; it never allows
            print(f"keycloak-mcp-admin-gateway: denied after {type(exc).__name__}", file=sys.stderr)
            status = DENY
        return Response(status_code=status)

    return Starlette(routes=[Route(ADMIN_CHECK_PATH, admin_check, methods=["GET"])])


def config_from_env(env: Mapping[str, str] | None = None) -> DelegationConfig:
    values = dict(os.environ if env is None else env)
    return DelegationConfig.for_gateway(KeycloakAuthConfig.from_env(values), values)


def port_from_env(env: Mapping[str, str] | None = None) -> int:
    value = (dict(os.environ if env is None else env).get(PORT_ENV) or "").strip() or str(ADMIN_CHECK_PORT)
    if not value.isascii() or not value.isdecimal() or not 1 <= int(value) <= 65535:
        raise DelegationError(f"{PORT_ENV} must be a TCP port from 1 to 65535")
    return int(value)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="keycloak-mcp-admin-gateway", description="Private Admin request checker")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=None, help=f"defaults to ${PORT_ENV} or {ADMIN_CHECK_PORT}")
    parser.add_argument("--check", action="store_true", help="validate the configuration and exit")
    args = parser.parse_args(argv)
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print("refusing to bind a non-loopback host", file=sys.stderr)
        return 2
    try:
        port = args.port if args.port is not None else port_from_env()
        config = config_from_env()
    except (TokenError, DelegationError) as exc:
        print(f"admin gateway configuration error: {exc}", file=sys.stderr)
        return 2
    if args.check:
        print(f"admin gateway ready: 127.0.0.1:{port}{ADMIN_CHECK_PATH} for {config.admin_path}")
        return 0
    delegate = DelegatedAdmin(config)
    import uvicorn

    config_uvicorn = uvicorn.Config(build_app(delegate), host=args.host, port=port, log_level="warning")

    async def serve() -> None:
        try:
            await uvicorn.Server(config_uvicorn).serve()
        finally:
            await delegate.aclose()

    print(f"keycloak-mcp-admin-gateway: http 127.0.0.1:{port}{ADMIN_CHECK_PATH}", file=sys.stderr)
    asyncio.run(serve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
