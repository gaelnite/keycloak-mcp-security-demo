"""Discovery, authentication and scope gates through the MCP transports."""

from __future__ import annotations

import json
import sys
import time
import unittest
from contextlib import asynccontextmanager
from pathlib import Path
from unittest.mock import patch

from tests.test_server_gate import HAVE_MCP

if HAVE_MCP:
    import anyio
    import httpx
    import jwt
    from cryptography.hazmat.primitives.asymmetric import ec
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    import server
    from auth import JwksCache, TokenError
    from pep import Decision


ISSUER = "https://kc.example:8443/realms/lab"
RESOURCE = "https://mcp.example:9443/admin/mcp"
METADATA = "https://mcp.example:9443/.well-known/oauth-protected-resource/admin/mcp"
CLIENT_ID = "desktop"
PROTOCOL = "2025-11-25"
USER_SCOPE = "keycloak.users.read"
CLIENT_SCOPE = "keycloak.clients.read"
OPTIONS = {
    "KC_ISSUER": ISSUER,
    "KC_URL": "https://kc.example:8443",
    "KC_ALLOWED_CLIENT_IDS": CLIENT_ID,
}


class RecordingPep:
    def __init__(self) -> None:
        self.calls = []
        self.rejections = []

    def authorize(self, spec, *, realm, **kwargs):
        self.calls.append(spec.name)
        return Decision("allow" if realm == "lab" else "deny", reasons=("fixture-policy",))

    async def authorize_async(self, spec, **kwargs):
        # server._evaluate must go through the async form; if it ever calls the
        # blocking one directly again, these doubles fail loudly instead of
        # silently blocking the loop.
        return self.authorize(spec, **kwargs)

    def audit_rejection(self, tool, principal_type, principal_id, realm, *, reason, detail,
                        approval_jti=None):
        self.rejections.append({"tool": tool.name, "reason": reason, "detail": detail})


@unittest.skipUnless(HAVE_MCP, "the MCP SDK is required for HTTP discovery tests")
class McpTransportTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.key = ec.generate_private_key(ec.SECP256R1())
        cls.jwk = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(cls.key.public_key()))
        cls.jwk.update(kid="test-key", alg="ES256", use="sig")

    @asynccontextmanager
    async def running(self, *, resource=RESOURCE):
        settings = {"KC_MCP_RESOURCE_URL": resource} if resource else {"KC_AUDIENCE": "opaque-mcp"}
        config = server.ServerConfig.from_env({**OPTIONS, **settings})
        self.audience = config.auth.audience
        self.path = config.auth.protected_resource.path if resource else "/mcp"
        self.session = {}
        self.admin_requests = []
        self.jwks_requests = []
        self.pep = RecordingPep()

        def jwks_response(request):
            self.jwks_requests.append(request)
            return httpx.Response(200, json={"keys": [self.jwk]})

        def admin_response(request):
            self.admin_requests.append(request)
            return httpx.Response(200, json=[{"username": "fixture-user"}])

        jwks = JwksCache(config.auth.jwks_url, transport=httpx.MockTransport(jwks_response))
        verifier = server.KeycloakTokenVerifier(config.auth, jwks=jwks)
        admin = server.KeycloakAdmin(
            config.base_url, server.current_token, transport=httpx.MockTransport(admin_response)
        )
        runtime = server.Runtime(config, self.pep, admin)
        mcp, _ = server.build_mcp(config)
        app = server.build_http_app(mcp, verifier)
        base_url = f"https://{config.auth.protected_resource.authority}" if resource else "http://localhost:8766"
        with patch.object(server, "_RUNTIME", runtime):
            async with mcp.session_manager.run(), httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url=base_url
            ) as http:
                self.http = http
                try:
                    yield http
                finally:
                    await admin.aclose()
                    await verifier.aclose()

    def token(self, scopes="", **claims) -> str:
        now = int(time.time())
        payload = {
            "iss": ISSUER,
            "aud": self.audience,
            "sub": "fixture-subject",
            "azp": CLIENT_ID,
            "scope": scopes,
            "iat": now,
            "exp": now + 300,
            **claims,
        }
        return jwt.encode(payload, self.key, algorithm="ES256", headers={"kid": "test-key"})

    async def request(self, method, token, *, params=None, request_id=1, headers=None):
        envelope = {"jsonrpc": "2.0", "method": method}
        if request_id is not None:
            envelope["id"] = request_id
        if params is not None:
            envelope["params"] = params
        return await self.http.post(
            self.path,
            json=envelope,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json, text/event-stream",
                **self.session,
                **(headers or {}),
            },
        )

    async def initialize(self, token):
        response = await self.request(
            "initialize",
            token,
            params={"protocolVersion": PROTOCOL, "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}},
        )
        self.assertEqual(response.status_code, 200, response.text)
        result = self.rpc_message(response)["result"]
        self.assertEqual(result["protocolVersion"], PROTOCOL)
        self.session = {"Mcp-Session-Id": response.headers["Mcp-Session-Id"], "MCP-Protocol-Version": PROTOCOL}
        initialized = await self.request("notifications/initialized", token, request_id=None)
        self.assertEqual(initialized.status_code, 202)

    async def call(self, token, name="list_users", arguments=None):
        params = {"name": name, "arguments": {"realm": "lab"} if arguments is None else arguments}
        return await self.request("tools/call", token, params=params, request_id=3)

    @staticmethod
    def rpc_message(response):
        if response.headers["content-type"].startswith("text/event-stream"):
            event = next(line.removeprefix("data: ") for line in response.text.splitlines() if line.startswith("data: "))
            return json.loads(event)
        return response.json()

    async def test_public_metadata_and_challenge_match_despite_forwarded_headers(self):
        async with self.running() as http:
            forwarded = {
                "Host": "untrusted.example",
                "Forwarded": "proto=http;host=untrusted.example",
                "X-Forwarded-Host": "untrusted.example",
                "X-Forwarded-Proto": "http",
                "X-Forwarded-Prefix": "/untrusted",
            }
            response = await http.post(self.path, headers=forwarded)
            self.assertEqual(response.status_code, 401)
            self.assertEqual(response.headers["WWW-Authenticate"], f'Bearer resource_metadata="{METADATA}"')
            metadata = await http.get(METADATA, headers={**forwarded, "Authorization": "Bearer invalid"})
            self.assertEqual(metadata.status_code, 200)
            self.assertEqual(metadata.json(), {
                "resource": RESOURCE, "authorization_servers": [ISSUER], "bearer_methods_supported": ["header"],
            })
            self.assertEqual((await http.head(METADATA)).status_code, 200)
            self.assertEqual((await http.get("/healthz")).status_code, 200)
            self.assertEqual((await http.get("/.well-known/oauth-protected-resource")).status_code, 401)
            self.assertEqual((await http.post(METADATA)).status_code, 401)
            self.assertEqual(self.jwks_requests, [])
            self.assertEqual(self.admin_requests, [])

    async def test_empty_grant_can_initialize_and_list_tools(self):
        async with self.running():
            token = self.token()
            await self.initialize(token)
            response = await self.request("tools/list", token, request_id=2)
            self.assertEqual(response.status_code, 200)
            self.assertIn("list_users", [tool["name"] for tool in response.json()["result"]["tools"]])
            self.assertEqual([str(request.url) for request in self.jwks_requests], [
                f"{ISSUER}/protocol/openid-connect/certs",
            ])
            self.assertEqual(self.pep.calls, [])
            self.assertEqual(self.admin_requests, [])

    async def test_same_session_uses_current_grants_and_only_challenges_for_this_tool(self):
        async with self.running():
            await self.initialize(self.token(f"{USER_SCOPE} {CLIENT_SCOPE}"))
            denied = await self.call(self.token(CLIENT_SCOPE))
            self.assertEqual(denied.status_code, 403, denied.text)
            self.assertEqual(
                denied.headers["WWW-Authenticate"],
                f'Bearer resource_metadata="{METADATA}", error="insufficient_scope", scope="{USER_SCOPE}"',
            )
            self.assertEqual(denied.json()["id"], 3)
            self.assertEqual(self.pep.calls, [])
            self.assertEqual([record["reason"] for record in self.pep.rejections], ["scope_missing"])
            self.assertEqual(self.admin_requests, [])

            # Reauthorization can keep the same session. Use the new bearer downstream.
            current = self.token(USER_SCOPE, jti="reauthorized")
            allowed = await self.call(current)
            self.assertEqual(allowed.status_code, 200, allowed.text)
            self.assertNotIn("WWW-Authenticate", allowed.headers)
            user = json.loads(allowed.json()["result"]["content"][0]["text"])
            self.assertEqual(user, {"username": "fixture-user"})
            self.assertEqual(self.pep.calls, ["list_users"])
            self.assertEqual(len(self.admin_requests), 1)
            self.assertEqual(self.admin_requests[0].url.path, "/admin/realms/lab/users")
            self.assertEqual(self.admin_requests[0].headers["Authorization"], f"Bearer {current}")

    async def test_bad_audience_and_malformed_token_are_authentication_errors(self):
        async with self.running():
            valid = self.token(USER_SCOPE)
            await self.initialize(valid)
            header, _, signature = valid.split(".")
            for token in (self.token(USER_SCOPE, aud="opaque-mcp"), f"{header}.bm90LWpzb24.{signature}"):
                denied = await self.call(token)
                self.assertEqual(denied.status_code, 401)
                self.assertEqual(denied.headers["WWW-Authenticate"],
                                 f'Bearer resource_metadata="{METADATA}", error="invalid_token"')
            self.assertEqual(self.pep.calls, [])
            self.assertEqual(self.admin_requests, [])

    async def test_policy_unknown_tool_and_invalid_arguments_do_not_request_scopes(self):
        async with self.running():
            token = self.token(USER_SCOPE)
            await self.initialize(token)
            responses = (
                await self.call(token, arguments={"realm": "outside-lab"}),
                await self.call(self.token(), name="config_cli_diff", arguments={}),
                await self.call(self.token(), name="config_cli_apply", arguments={}),
                await self.call(self.token(), arguments={}),
            )
            for response in responses:
                self.assertEqual(response.status_code, 200, response.text)
                self.assertNotIn("WWW-Authenticate", response.headers)
                self.assertEqual(response.json()["id"], 3)
            self.assertIn("Cedar denied", responses[0].text)
            self.assertTrue(responses[1].json()["result"]["isError"])
            self.assertIn("Unknown tool: config_cli_diff", responses[1].text)
            self.assertTrue(responses[2].json()["result"]["isError"])
            self.assertIn("Unknown tool: config_cli_apply", responses[2].text)
            self.assertTrue(responses[3].json()["result"]["isError"])
            invalid_version = await self.request(
                "tools/call", self.token(), params={"name": "list_users"},
                headers={"MCP-Protocol-Version": "unsupported"},
            )
            self.assertEqual(invalid_version.status_code, 400)
            self.assertNotIn("WWW-Authenticate", invalid_version.headers)
            self.assertEqual(self.pep.calls, ["list_users"])
            self.assertEqual(self.admin_requests, [])

    async def test_a_different_subject_cannot_use_the_same_mcp_session(self):
        async with self.running():
            await self.initialize(self.token(USER_SCOPE))
            denied = await self.call(self.token(USER_SCOPE, sub="other-subject"))
            self.assertEqual(denied.status_code, 404)
            self.assertNotIn("WWW-Authenticate", denied.headers)
            self.assertEqual(self.pep.calls, [])
            self.assertEqual(self.admin_requests, [])

    async def test_legacy_opaque_audience_still_uses_sse_and_json_rpc_denials(self):
        async with self.running(resource=None) as http:
            no_token = await http.post(self.path)
            self.assertEqual(no_token.headers["WWW-Authenticate"], 'Bearer error="invalid_token"')
            self.assertEqual((await http.get("/.well-known/oauth-protected-resource/mcp")).status_code, 401)
            await self.initialize(self.token(USER_SCOPE))
            denial = await self.call(self.token())
            self.assertEqual(denial.status_code, 200)
            self.assertNotIn("WWW-Authenticate", denial.headers)
            self.assertTrue(denial.headers["content-type"].startswith("text/event-stream"))
            self.assertIn("lacks the required scope", json.dumps(self.rpc_message(denial)))
            self.assertEqual(self.pep.calls, [])
            self.assertEqual([record["reason"] for record in self.pep.rejections], ["scope_missing"])
            self.assertEqual(self.admin_requests, [])

    async def test_resource_at_origin_has_origin_metadata(self):
        resource = "https://mcp.example"
        async with self.running(resource=resource) as http:
            metadata = await http.get("/.well-known/oauth-protected-resource")
            self.assertEqual(metadata.json()["resource"], resource)
            await self.initialize(self.token())

    def test_resource_discovery_requires_exact_audience_match(self):
        with self.assertRaisesRegex(TokenError, "exactly match"):
            server.ServerConfig.from_env({**OPTIONS, "KC_MCP_RESOURCE_URL": RESOURCE, "KC_AUDIENCE": "opaque"})
        valid = server.ServerConfig.from_env({**OPTIONS, "KC_MCP_RESOURCE_URL": RESOURCE, "KC_AUDIENCE": RESOURCE})
        self.assertEqual(valid.auth.audience, RESOURCE)

    def test_invalid_or_conflicting_canonical_urls_fail_configuration(self):
        for value in (
            "http://mcp.example/mcp", "https://user@mcp.example/mcp", "https://mcp.example/mcp?",
            "https://mcp.example/mcp#fragment", "https://mcp.example/mcp/", "https://mcp.example/./mcp",
            "https://mcp.example/%2Fmcp", "https://mcp.example:99999/mcp", "https://mcp.example/healthz",
            "https://mcp.example/.well-known/oauth-protected-resource",
        ):
            with self.subTest(value=value), self.assertRaisesRegex(TokenError, "KC_MCP_RESOURCE_URL"):
                server.ServerConfig.from_env({**OPTIONS, "KC_MCP_RESOURCE_URL": value})

    async def test_stdio_still_initializes_and_enforces_token_scope(self):
        # The child runs the normal CLI over OS pipes. Replace external services
        # with fixtures so that the smoke test needs neither Keycloak nor Node.
        child = """
import json
import os
import sys
from unittest.mock import patch

sys.path.insert(0, sys.argv[1])
sys.path.insert(0, sys.argv[2])
import server
from tests.test_mcp_transport import RecordingPep
from auth import JwksCache, KeycloakTokenVerifier
from httpx import MockTransport, Response

def verifier(config):
    jwks = JwksCache(config.jwks_url, transport=MockTransport(
        lambda _: Response(200, json={"keys": [json.loads(os.environ["TEST_JWK"])]})
    ))
    return KeycloakTokenVerifier(config, jwks=jwks)

class StdioPep(RecordingPep):
    def close(self):
        pass

with patch.object(server, "KeycloakTokenVerifier", verifier), patch.object(
    server, "build_runtime",
    lambda config: server.Runtime(
        config, StdioPep(), server.KeycloakAdmin(config.base_url, server.current_token)
    ),
):
    raise SystemExit(server.main(["--transport", "stdio"]))
"""
        project = Path(__file__).resolve().parents[1]
        self.audience = "opaque-mcp"
        parameters = StdioServerParameters(
            command=sys.executable,
            args=["-c", child, str(project), str(project / "mcp")],
            env={
                **OPTIONS,
                "KC_AUDIENCE": self.audience,
                "KC_MCP_ACCESS_TOKEN": self.token("keycloak.extensions.read"),
                "TEST_JWK": json.dumps(self.jwk),
            },
        )

        with anyio.fail_after(10):
            async with (
                stdio_client(parameters) as (reader, writer),
                ClientSession(reader, writer) as client,
            ):
                result = await client.initialize()
                self.assertEqual(result.protocolVersion, PROTOCOL)
                tools = await client.list_tools()
                self.assertIn("get_extension_inventory", [tool.name for tool in tools.tools])
                allowed = await client.call_tool("get_extension_inventory")
                self.assertIn("core", allowed.content[0].text)
                denied = await client.call_tool("list_users", {"realm": "lab"})
                self.assertIn("lacks the required scope", denied.content[0].text)
