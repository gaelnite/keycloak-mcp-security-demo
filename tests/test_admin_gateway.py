"""The private Admin gateway's checker answers from a process it does not constrain.

Two things are asserted here.  The first is the decision matrix: the same bearer that is
allowed on one Admin route is denied on every other, and a checker that cannot parse a
request denies rather than allows.  The second is the topology: the route is served by
``mcp/admin_gateway.py`` and not by ``mcp/server.py``, and the sidecar that runs it is
configured without any Workload API credential, so compromising it cannot produce a token
the gateway would accept.
"""

from __future__ import annotations

import asyncio
import itertools
import sys
import time
import unittest
from pathlib import Path

from tests.test_server_gate import HAVE_MCP

LAB = Path(__file__).resolve().parents[1]
sys.path.append(str(LAB / "deploy" / "docker"))

if HAVE_MCP:
    import certifi
    import httpx
    import jwt
    from cryptography.hazmat.primitives.asymmetric import ec

    import admin_gateway
    import bootstrap
    import server
    from auth import KeycloakAuthConfig, TokenClaims
    from delegation import (
        ADMIN_CHECK_PATH,
        ADMIN_CHECK_PORT,
        WORKLOAD_ENV,
        DelegatedAdmin,
        DelegationConfig,
        DelegationError,
    )
    from tool_registry import CLIENTS_READ, LOCALE_FIXTURE_ID, USER_LOCALE, USERS_READ

ISSUER = "https://localhost:49448/realms/lab"
RESOURCE = "https://localhost:49448/mcp"
DESKTOP = "desktop"
ADMIN_BASE = "/admin/realms/lab"
OTHER_USER = "/admin/realms/lab/users/11111111-2222-3333-4444-555555555555"
FIXTURE = f"{ADMIN_BASE}/users/{LOCALE_FIXTURE_ID}"
USERS = f"{ADMIN_BASE}/users"
CLIENTS = f"{ADMIN_BASE}/clients"


def gateway_env(**overrides):
    env = {
        "KC_ISSUER": ISSUER,
        "KC_MCP_RESOURCE_URL": RESOURCE,
        "KC_ALLOWED_CLIENT_IDS": DESKTOP,
        "KC_MCP_INTERACTIVE_CLIENT_IDS": DESKTOP,
        "KC_MCP_DELEGATED_ADMIN_URL": "https://localhost:8801",
        "KC_MCP_DELEGATED_CA_FILE": certifi.where(),
    }
    env.update(overrides)
    return env


@unittest.skipUnless(HAVE_MCP, "the ASGI checker needs the runtime dependencies")
class AdminGatewayDecisionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        env = gateway_env()
        self.config = DelegationConfig.for_gateway(KeycloakAuthConfig.from_env(env), env)
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.calls: list[httpx.Request] = []
        delegate = DelegatedAdmin(self.config, transport=httpx.MockTransport(self._upstream), jwks=self)
        self.addAsyncCleanup(delegate.aclose)
        app = admin_gateway.build_app(delegate)
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1")
        self.addAsyncCleanup(self.client.aclose)

    def _upstream(self, request):
        # The checker verifies a signature against the injected JWKS.  A recorded request
        # here would mean it was willing to fetch a token or call the Admin API itself.
        self.calls.append(request)
        return httpx.Response(599)

    async def get_key(self, kid):
        self.assertEqual(kid, "test-key")
        return self.key.public_key()

    def claims(self, capability, *, now=None):
        now = int(time.time()) if now is None else now
        return {
            "iss": ISSUER, "sub": "subject-under-test", "aud": self.config.admin_audience,
            "azp": capability.requester_audience(RESOURCE), "typ": "Bearer",
            "scope": f"kc-admin-api {capability.scope}", "iat": now, "exp": now + 40,
        }

    def token(self, capability, **overrides):
        return jwt.encode(
            {**self.claims(capability), **overrides}, self.key, algorithm="ES256", headers={"kid": "test-key"}
        )

    async def ask(self, *, method="GET", path=USERS, query="max=10&briefRepresentation=true",
                  capability=USERS_READ, bearer=..., headers=None):
        sent = {"x-admin-method": method, "x-admin-path": path, "x-admin-query": query, **(headers or {})}
        if bearer is not None:
            sent["authorization"] = f"Bearer {self.token(capability) if bearer is ... else bearer}"
        response = await self.client.get(ADMIN_CHECK_PATH, headers=sent)
        self.assertEqual(self.calls, [], "the checker must decide without calling out to Keycloak")
        return response

    async def test_permitted_routes_answer_204(self):
        for capability, method, path, query in (
            (USERS_READ, "GET", USERS, "max=10&briefRepresentation=true"),
            (USERS_READ, "GET", FIXTURE, ""),
            (CLIENTS_READ, "GET", CLIENTS, "max=5&search=desk"),
            (CLIENTS_READ, "GET", CLIENTS, "max=2&clientId=desktop"),
            (USER_LOCALE, "PUT", FIXTURE, ""),
        ):
            with self.subTest(capability=capability.scope, method=method, path=path, query=query):
                self.assertEqual((await self.ask(method=method, path=path, query=query, capability=capability)).status_code, 204)

    async def test_a_token_only_answers_for_its_own_route(self):
        for capability, method, path, query in (
            # Wrong route for the capability, including the realm's other Admin collections.
            (USERS_READ, "GET", CLIENTS, "max=5"),
            (CLIENTS_READ, "GET", USERS, "max=5&briefRepresentation=true"),
            (USER_LOCALE, "GET", FIXTURE, ""),
            (USER_LOCALE, "POST", FIXTURE, ""),
            (USER_LOCALE, "PUT", OTHER_USER, ""),
            (USER_LOCALE, "PUT", FIXTURE, "unexpected=1"),
            # Outside the shapes the capability is allowed to touch at all.
            (USERS_READ, "GET", f"{FIXTURE}/consent", ""),
            (USERS_READ, "GET", f"{USERS}/..%2fconsent", ""),
            (USERS_READ, "DELETE", USERS, ""),
            (USERS_READ, "GET", USERS, "max=51&briefRepresentation=true"),
            (USERS_READ, "GET", USERS, "max=0&briefRepresentation=true"),
            (USERS_READ, "GET", USERS, "max=5"),
            (USERS_READ, "GET", USERS, "max=5&max=6&briefRepresentation=true"),
            (USERS_READ, "GET", USERS, "max=5&briefRepresentation=true&realm=master"),
            (CLIENTS_READ, "GET", CLIENTS, "max=5&briefRepresentation=true"),
            (USERS_READ, "GET", "/admin/realms/other/users", "max=5&briefRepresentation=true"),
            (USERS_READ, "GET", "/realms/lab/users", "max=5&briefRepresentation=true"),
            (USERS_READ, "GET", "/admin/realms/lab", ""),
        ):
            with self.subTest(capability=capability.scope, method=method, path=path, query=query):
                self.assertEqual((await self.ask(method=method, path=path, query=query, capability=capability)).status_code, 403)

    async def test_a_bearer_the_checker_cannot_verify_is_denied(self):
        no_audience = jwt.encode(
            {"iss": ISSUER, "exp": int(time.time()) + 60}, self.key, algorithm="ES256", headers={"kid": "test-key"}
        )
        for bearer, label in (
            (None, "no Authorization header"),
            ("", "empty Authorization header"),
            ("Basic dXNlcjpwYXNz", "wrong scheme"),
            ("Bearer", "scheme without a token"),
            ("Bearer not-a-jwt", "malformed token"),
            (no_audience, "token without the required claims"),
        ):
            with self.subTest(label):
                self.assertEqual((await self.ask(bearer=bearer)).status_code, 403)

    async def test_a_token_outside_the_capability_ceiling_is_denied(self):
        expired = int(time.time()) - 5
        for overrides in (
            {"aud": RESOURCE},
            {"aud": [self.config.admin_audience, RESOURCE]},
            {"azp": CLIENTS_READ.requester_audience(RESOURCE)},
            {"typ": "ID"},
            {"scope": f"kc-admin-api {USERS_READ.scope} {CLIENTS_READ.scope}"},
            {"exp": int(time.time()) + 600},
            {"iat": expired - 40, "exp": expired},
            {"sub": ""},
            {"realm_access": {"roles": ["manage-users"]}},
            {"resource_access": {"realm-management": {"roles": ["view-users", "manage-users"]}}},
            {"resource_access": {"account": {"roles": ["view-profile"]}}},
        ):
            with self.subTest(overrides=sorted(overrides)):
                self.assertEqual((await self.ask(bearer=self.token(USERS_READ, **overrides))).status_code, 403)

    async def test_the_inbound_user_token_is_not_a_capability(self):
        # The desktop token the human presented to MCP authorises the tool call, not the
        # Admin request; only the exchanged token passes here.
        inbound = jwt.encode(
            {**self.claims(USERS_READ), "aud": RESOURCE, "azp": DESKTOP, "scope": USERS_READ.scope},
            self.key, algorithm="ES256", headers={"kid": "test-key"},
        )
        self.assertEqual((await self.ask(bearer=inbound)).status_code, 403)

    async def test_the_checker_serves_nothing_but_the_check(self):
        for path in ("/healthz", "/", ADMIN_CHECK_PATH + "/extra"):
            with self.subTest(path=path):
                self.assertNotEqual((await self.client.get(path)).status_code, 204)
        self.assertEqual((await self.client.request("POST", ADMIN_CHECK_PATH)).status_code, 405)

    async def test_the_snapshot_headers_the_gateway_must_set_are_required(self):
        # A request that arrives without the method/path snapshot is not an Admin request
        # the gateway can reason about, so it is denied rather than treated as harmless.
        self.assertEqual((await self.client.get(ADMIN_CHECK_PATH)).status_code, 403)
        self.assertEqual((await self.client.get(ADMIN_CHECK_PATH, headers={"x-admin-method": "GET"})).status_code, 403)


@unittest.skipUnless(HAVE_MCP, "the ASGI checker needs the runtime dependencies")
class CheckerTopologyTests(unittest.TestCase):
    """The check must be structurally separate from the process it constrains."""

    def test_the_mcp_process_does_not_host_the_check(self):
        source = (LAB / "mcp/server.py").read_text()
        self.assertNotIn("delegated_admin_check", source)
        self.assertNotIn("admin_check", source)
        self.assertNotIn("gateway_capability", source)
        self.assertFalse(hasattr(server, "ADMIN_CHECK_PATH"))

    def test_the_sidecar_configuration_refuses_workload_credentials(self):
        for key in WORKLOAD_ENV:
            env = gateway_env(**{key: "/delegate/spire-agent"})
            auth = KeycloakAuthConfig.from_env(env)
            with self.subTest(key=key), self.assertRaises(DelegationError):
                DelegationConfig.for_gateway(auth, env)
        auth = KeycloakAuthConfig.from_env(gateway_env())
        with self.assertRaises(DelegationError):
            DelegationConfig.for_gateway(auth, gateway_env(KC_MCP_DELEGATED_ADMIN_URL=""))

    def test_a_configured_checker_cannot_exchange_even_if_asked(self):
        env = gateway_env()
        config = DelegationConfig.for_gateway(KeycloakAuthConfig.from_env(env), env)
        self.assertFalse(config.can_exchange)
        delegate = DelegatedAdmin(config, transport=httpx.MockTransport(lambda request: httpx.Response(599)), jwks=object())
        caller = TokenClaims(
            subject="subject-under-test", client_id=DESKTOP, scopes=frozenset({USERS_READ.scope}), realm="lab",
            admin=False, expires_at=time.time() + 120, issuer=ISSUER, audience=RESOURCE,
            roles=frozenset({USERS_READ.role}), interactive=True,
        )
        with self.assertRaises(DelegationError) as raised:
            asyncio.run(delegate.exchange(USERS_READ, caller, "inbound-token"))
        self.assertIn("Workload API", str(raised.exception))

    def test_nginx_points_at_the_injected_sidecar_port(self):
        listener = bootstrap.admin_listener()
        self.assertIn(f"proxy_pass http://127.0.0.1:{ADMIN_CHECK_PORT}{ADMIN_CHECK_PATH};", listener)
        self.assertNotIn("127.0.0.1:8800/__delegated_admin_check", listener)
        self.assertNotIn("@ADMIN_CHECK_PORT@", listener)
        self.assertIn("listen 127.0.0.1:8801 ssl;", listener)

    def test_the_sidecar_container_mounts_no_workload_identity(self):
        lines = (LAB / "deploy/docker/compose.delegated.yaml").read_text().splitlines()
        start = lines.index("  admin-gateway:")
        block = "\n".join(itertools.takewhile(lambda line: line.startswith("    "), lines[start + 1:]))
        self.assertIn("image: ${COMPOSE_PROJECT_NAME}-mcp", block)
        self.assertIn(f"http://127.0.0.1:{ADMIN_CHECK_PORT}{ADMIN_CHECK_PATH}", block)
        # The port comes from the constant the nginx listener is built from, so the
        # compose file must not offer a second, drift-prone way to set it.
        self.assertNotIn("KC_MCP_ADMIN_CHECK_PORT", block)
        self.assertIn("edge-trust:/trust:ro", block)
        self.assertIn("entrypoint: [python, /app/mcp/admin_gateway.py]", block)
        self.assertNotIn("workload-socket", block)
        self.assertNotIn("delegate:", block)
        self.assertNotIn("pid:", block)


if __name__ == "__main__":
    unittest.main()
