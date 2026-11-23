"""Fail-closed exchange and operation shape tests using signed fixture tokens."""

from __future__ import annotations

import time
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs

from tests.test_server_gate import HAVE_MCP

if HAVE_MCP:
    import certifi
    import httpx
    import jwt
    from cryptography.hazmat.primitives.asymmetric import ec

    from auth import KeycloakAuthConfig, TokenClaims
    from delegation import (
        ACCESS_TOKEN_TYPE,
        DelegatedAdmin,
        DelegationConfig,
        DelegationError,
        gateway_capability,
        operation_for,
    )
    from tool_registry import CLIENTS_READ, LOCALE_FIXTURE_ID, TOOLS_BY_NAME, USER_LOCALE, USERS_READ

ISSUER = "https://localhost:49448/realms/lab"
RESOURCE = "https://localhost:49448/mcp"
DESKTOP = "desktop"
INBOUND = "fixture-inbound-bearer"


@unittest.skipUnless(HAVE_MCP, "the MCP runtime is required for delegation tests")
class DelegationTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        auth = KeycloakAuthConfig.from_env({
            "KC_ISSUER": ISSUER, "KC_MCP_RESOURCE_URL": RESOURCE,
            "KC_ALLOWED_CLIENT_IDS": DESKTOP, "KC_MCP_INTERACTIVE_CLIENT_IDS": DESKTOP,
        })
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.config = DelegationConfig(auth, "https://localhost:8801", certifi.where(), "mcp.demo", "/socket", "/exe")
        self.calls = []
        self.caller = TokenClaims(
            subject="subject", client_id=DESKTOP, scopes=frozenset({USERS_READ.scope}), realm="lab", admin=False,
            expires_at=time.time() + 120, issuer=ISSUER, audience=RESOURCE,
            roles=frozenset({USERS_READ.role}), interactive=True,
        )

    async def get_key(self, kid):
        self.assertEqual(kid, "test-key")
        return self.key.public_key()

    def token(self, **overrides):
        now = int(time.time())
        claims = {
            "iss": ISSUER, "sub": self.caller.subject, "aud": self.config.admin_audience,
            "azp": USERS_READ.requester_audience(RESOURCE), "typ": "Bearer",
            "scope": f"kc-admin-api {USERS_READ.scope}", "iat": now, "exp": now + 40,
            **overrides,
        }
        return jwt.encode(claims, self.key, algorithm="ES256", headers={"kid": "test-key"})

    def provider(self, exchanged):
        def upstream(request):
            self.calls.append(request)
            if request.url.path.endswith("/token"):
                return httpx.Response(200, json={
                    "access_token": exchanged, "token_type": "Bearer", "issued_token_type": ACCESS_TOKEN_TYPE,
                })
            return httpx.Response(200, json=[{
                "id": "user-id", "username": "fixture", "enabled": True,
                "email": "fixture@example.invalid", "secret": "fixture-secret", "credentials": [{}],
            }])
        client = DelegatedAdmin(self.config, transport=httpx.MockTransport(upstream), jwks=self)
        self.addAsyncCleanup(client.aclose)
        return client

    async def test_verified_distinct_token_and_projection(self):
        exchanged = self.token()
        provider = self.provider(exchanged)
        with patch("delegation.fetch_svid", return_value="fixture-workload-assertion") as fetched:
            result = await provider.dispatch(TOOLS_BY_NAME["list_users"], self.caller, INBOUND)
        self.assertEqual(result, [{"id": "user-id", "username": "fixture", "enabled": True}])
        fetch_args = fetched.call_args.args
        self.assertEqual(fetch_args[-2:], ("spiffe://mcp.demo/workload/mcp-exchange/keycloak.users.read", ISSUER))
        exchange, admin = self.calls
        self.assertEqual(parse_qs(exchange.content.decode())["subject_token"], [INBOUND])
        self.assertEqual(admin.headers["Authorization"], f"Bearer {exchanged}")
        self.assertEqual(str(admin.url).split("?")[0], "https://localhost:8801/admin/realms/lab/users")

    async def test_mismatched_or_overprivileged_token_stops_before_admin(self):
        for overrides in (
            {"sub": "other-subject"}, {"aud": [self.config.admin_audience, RESOURCE]},
            {"azp": CLIENTS_READ.requester_audience(RESOURCE)}, {"typ": "ID"},
            {"scope": f"kc-admin-api {USERS_READ.scope} {CLIENTS_READ.scope}"},
            {"resource_access": {"realm-management": {"roles": ["manage-users"]}}},
            {"exp": int(time.time()) + 120},
        ):
            with self.subTest(overrides=overrides):
                self.calls.clear()
                provider = self.provider(self.token(**overrides))
                with patch("delegation.fetch_svid", return_value="fixture-workload-assertion"), self.assertRaises(DelegationError):
                    await provider.dispatch(TOOLS_BY_NAME["list_users"], self.caller, INBOUND)
                self.assertEqual([request.url.path for request in self.calls], ["/realms/lab/protocol/openid-connect/token"])

    async def test_wrong_grant_stops_before_svid_or_network(self):
        provider = self.provider(self.token())
        with patch("delegation.fetch_svid") as fetched, self.assertRaises(DelegationError):
            await provider.dispatch(TOOLS_BY_NAME["list_clients"], self.caller, INBOUND)
        fetched.assert_not_called()
        self.assertEqual(self.calls, [])

    def test_locale_operation_controls_exact_target_body_and_gateway_method(self):
        spec = TOOLS_BY_NAME["set_user_locale"]
        operation = operation_for(spec, user_id=LOCALE_FIXTURE_ID, locale="de")
        self.assertEqual(operation.body, {"attributes": {"locale": ["de"]}})
        self.assertIsNone(operation.query)
        path = self.config.admin_path + operation.path
        self.assertEqual(gateway_capability(self.config.admin_path, "PUT", path), USER_LOCALE)
        self.assertEqual(gateway_capability(self.config.admin_path, "GET", path), USERS_READ)
        self.assertIsNone(gateway_capability(self.config.admin_path, "POST", path))
        with self.assertRaises(DelegationError):
            operation_for(spec, user_id="unmanaged", locale="de")
