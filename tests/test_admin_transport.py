"""Transport isolation for the Admin API client, which carries a bearer token on every call."""

from __future__ import annotations

import asyncio
import os
import ssl
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "mcp"))

import httpx  # noqa: E402

from auth import TokenError  # noqa: E402
from keycloak_admin import KeycloakAdmin  # noqa: E402


def _client(admin: KeycloakAdmin) -> httpx.AsyncClient:
    """Build the admin client, then close it, and hand back the configured client."""
    built: dict[str, httpx.AsyncClient] = {}

    async def run() -> None:
        try:
            built["client"] = await admin._http()
        finally:
            await admin.aclose()

    asyncio.run(run())
    return built["client"]


class AdminTransportTests(unittest.TestCase):
    def test_no_ambient_proxy_or_netrc_trust(self) -> None:
        """Every request here sends a bearer token; a stray proxy would read and steer it."""
        admin = KeycloakAdmin("https://kc.lab.local:8443", lambda: "caller-token")
        with patch.dict(
            os.environ,
            {
                "ALL_PROXY": "http://127.0.0.1:9",
                "HTTPS_PROXY": "http://127.0.0.1:9",
                "SSL_CERT_FILE": "",
                "SSL_CERT_DIR": "",
            },
        ):
            client = _client(admin)
        self.assertFalse(client.trust_env)
        self.assertFalse(client.follow_redirects)

    def test_the_named_ca_reaches_the_admin_connections(self) -> None:
        """`trust_env=False` also stops httpx reading SSL_CERT_FILE, so trust is explicit."""
        context = ssl.create_default_context()
        admin = KeycloakAdmin("https://kc.lab.local:8443", lambda: "caller-token")
        with (
            patch("keycloak_admin.ssl_trust", return_value=context) as trust,
            patch.dict(os.environ, {"SSL_CERT_FILE": "/trust/edge-ca.pem"}),
        ):
            client = _client(admin)
        self.assertIs(client._transport._pool._ssl_context, context)
        trust.assert_called_once_with()

    def test_a_named_ca_that_cannot_load_stops_the_server(self) -> None:
        admin = KeycloakAdmin("https://kc.lab.local:8443", lambda: "caller-token")
        with (
            patch.dict(os.environ, {"SSL_CERT_FILE": "/nonexistent/edge-ca.pem", "SSL_CERT_DIR": ""}),
            self.assertRaises(TokenError),
        ):
            _client(admin)

    def test_an_injected_transport_still_answers(self) -> None:
        """Unit tests and the demo's own checks drive this client with a mock transport."""
        seen: dict[str, str] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["url"] = str(request.url)
            seen["authorization"] = request.headers.get("Authorization", "")
            return httpx.Response(200, json={"id": "u1"})

        admin = KeycloakAdmin(
            "https://kc.lab.local:8443",
            lambda: "caller-token",
            transport=httpx.MockTransport(handler),
        )

        async def call() -> object:
            try:
                return await admin.get("/admin/realms/lab/users/u1")
            finally:
                await admin.aclose()

        self.assertEqual(asyncio.run(call()), {"id": "u1"})
        self.assertEqual(seen["url"], "https://kc.lab.local:8443/admin/realms/lab/users/u1")
        self.assertEqual(seen["authorization"], "Bearer caller-token")


if __name__ == "__main__":
    unittest.main()
