#!/usr/bin/env python3
"""Sign in with no tool scopes, then choose a subset for a Codex login."""

from __future__ import annotations

import argparse
import asyncio
import json
import shlex
import ssl
import sys
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlsplit

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "mcp"))

from auth import JwksCache, KeycloakAuthConfig, KeycloakTokenVerifier, TokenError
from desktop_oauth import DESKTOP_CLIENT_ID, DESKTOP_REDIRECT, DesktopAuthorization
from tool_registry import CAPABILITIES


def browser_code(flow: DesktopAuthorization) -> str:
    registered = urlsplit(DESKTOP_REDIRECT)
    code = None

    class CallbackHandler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            nonlocal code
            if self.headers.get("Host") != registered.netloc or urlsplit(self.path).path != registered.path:
                self.send_error(404)
                return
            try:
                code = flow.code_from_callback(f"http://{registered.netloc}{self.path}")
            except ValueError:
                self.send_error(400, "OAuth callback did not match this request")
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            self.wfile.write(b"Return to the terminal to choose MCP scopes.\n")

    with HTTPServer((registered.hostname, registered.port), CallbackHandler) as server:
        server.timeout = 1.0
        if not webbrowser.open(flow.start_url([], prompt="login")):
            raise ValueError("Could not open the Keycloak login in the default browser")
        deadline = time.monotonic() + 180
        while code is None and time.monotonic() < deadline:
            server.handle_request()
    if code is None:
        raise ValueError("Timed out waiting for the registered OAuth callback")
    return code


async def verified_roles(flow: DesktopAuthorization, token: str, trust: ssl.SSLContext) -> frozenset[str]:
    config = KeycloakAuthConfig.from_env({
        "KC_ISSUER": flow.issuer,
        "KC_MCP_RESOURCE_URL": flow.resource,
        "KC_ALLOWED_CLIENT_IDS": DESKTOP_CLIENT_ID,
        "KC_MCP_INTERACTIVE_CLIENT_IDS": DESKTOP_CLIENT_ID,
        "KC_CLOCK_SKEW": "0",
    })
    jwks = JwksCache(config.jwks_url, transport=httpx.AsyncHTTPTransport(verify=trust))
    verifier = KeycloakTokenVerifier(config, jwks=jwks)
    try:
        claims = await verifier.verify(token)
        if claims.scopes & CAPABILITIES.keys():
            raise ValueError("The provider issued tool scopes during the entitlement sign-in")
        return claims.roles
    finally:
        await verifier.aclose()


def login_command(name: str, resource: str, scopes: list[str]) -> str:
    settings = {
        "client_id": DESKTOP_CLIENT_ID,
        "resource": resource,
        "callback_url": DESKTOP_REDIRECT,
        "callback_port": urlsplit(DESKTOP_REDIRECT).port,
    }
    overrides = [part for key, value in settings.items() for part in ("-c", f"mcp_servers.{name}.oauth.{key}={json.dumps(value)}")]
    return shlex.join(["codex", *overrides, "mcp", "login", name, "--scopes", ",".join(["openid", *scopes])])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=49443, help="Docker demo's HTTPS port")
    parser.add_argument("--ca", type=Path, required=True, help="Docker demo's HTTPS CA file")
    parser.add_argument("--name", default="keycloak-demo", help="Name of the configured Codex MCP server")
    args = parser.parse_args()
    if not args.name or not all(character.isascii() and (character.isalnum() or character in "_-") for character in args.name):
        parser.error("--name must contain letters, numbers, hyphens or underscores")
    base = f"https://localhost:{args.port}"
    flow = DesktopAuthorization(base + "/realms/lab", base + "/mcp")
    trust = ssl.create_default_context(cafile=str(args.ca))
    with httpx.Client(verify=trust, trust_env=False, timeout=10) as client:
        flow.validate_discovery(client)
        code = browser_code(flow)
        exchange = client.post(flow.token_endpoint, data=flow.token_request(code))
        if exchange.status_code != 200:
            raise ValueError(f"Keycloak rejected the code with HTTP {exchange.status_code}")
        roles = asyncio.run(verified_roles(flow, exchange.json()["access_token"], trust))

    eligible = [cap for cap in CAPABILITIES.values() if cap.role in roles]
    selected = []
    if eligible:
        for index, cap in enumerate(eligible, 1):
            print(f"{index}. {cap.label} ({cap.scope})")
        selection = input("Select any option numbers, separated by spaces, or Enter for no tool scopes.\n")
        try:
            indices = {int(item) for item in selection.split()}
            if not indices <= set(range(1, len(eligible) + 1)):
                raise ValueError
        except ValueError:
            raise ValueError("Selection must use the displayed option numbers") from None
        selected = [cap.scope for index, cap in enumerate(eligible, 1) if index in indices]
    else:
        print("This user has no tool scopes to select.")
    print(login_command(args.name, flow.resource, selected))


if __name__ == "__main__":
    try:
        main()
    except (EOFError, KeyError, OSError, ValueError, TokenError, httpx.HTTPError) as exc:
        # HTTP error strings can include request query parameters.
        sys.exit(type(exc).__name__ if isinstance(exc, httpx.HTTPError) else str(exc))
