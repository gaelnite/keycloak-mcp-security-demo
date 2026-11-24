"""Server-side gate order tests (need the MCP SDK; skipped on bare Python)."""

from __future__ import annotations

import asyncio
import sys
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

LAB = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(LAB / "mcp"))

try:
    import importlib.util

    # The lab directory itself is named mcp, so importing "mcp" can succeed as a
    # namespace package. Probe a real SDK submodule instead.
    HAVE_MCP = importlib.util.find_spec("mcp.server.fastmcp") is not None
except (ImportError, ValueError):  # pragma: no cover - depends on the interpreter
    HAVE_MCP = False

if HAVE_MCP:
    import server
    from auth import TokenClaims, TokenError
    from pep import Decision


class _RecordingPep:
    def __init__(self) -> None:
        self.calls = 0
        self.rejections: list[dict] = []
        self.audit_error: OSError | None = None

    def authorize(self, *args, **kwargs):
        self.calls += 1
        return Decision("deny", reasons=("test-deny",))

    async def authorize_async(self, *args, **kwargs):
        # The server awaits this form: a blocking authorize() on the event loop
        # would stall every other session. See mcp/pep.py::authorize_async.
        return self.authorize(*args, **kwargs)

    def audit_rejection(self, tool, principal_type, principal_id, realm, *, reason, detail,
                        approval_jti=None):
        if self.audit_error is not None:
            raise self.audit_error
        self.rejections.append({"tool": tool.name, "principal_type": principal_type,
                                "principal": principal_id, "realm": realm, "reason": reason,
                                "detail": detail, "jti": approval_jti})


@unittest.skipUnless(HAVE_MCP, "the MCP SDK is required for server gate tests")
class ServerGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.config = server.ServerConfig.from_env(
            {
                "KC_ISSUER": "https://kc.lab.local:8443/realms/lab",
                "KC_AUDIENCE": "https://mcp.lab.local/mcp",
                "KC_URL": "https://kc.lab.local:8443",
                "KC_ALLOWED_CLIENT_IDS": "https://cimd.lab.local:8444/client-metadata.json",
            }
        )
        cls.mapped_config = server.ServerConfig.from_env(
            {
                "KC_ISSUER": "https://kc.lab.local:8443/realms/lab",
                "KC_AUDIENCE": "https://mcp.lab.local/mcp",
                "KC_URL": "https://kc.lab.local:8443",
                "KC_ALLOWED_CLIENT_IDS": "https://cimd.lab.local:8444/client-metadata.json",
                "KC_MCP_CLIENT_ENTITY_MAP": '{"another-client":"mcp-claude"}',
            }
        )

    def setUp(self) -> None:
        self._old_runtime = server._RUNTIME
        self.pep = _RecordingPep()
        server._RUNTIME = server.Runtime(config=self.config, pep=self.pep, admin=None)

    def tearDown(self) -> None:
        server._RUNTIME = self._old_runtime
        server._CLAIMS.set(None)

    def claims(self, *, scopes, admin=False) -> TokenClaims:
        return TokenClaims(
            subject="alice",
            client_id="https://cimd.lab.local:8444/client-metadata.json",
            scopes=frozenset(scopes),
            realm="lab",
            admin=admin,
            expires_at=9_999_999_999,
            issuer=self.config.auth.issuer,
            audience=self.config.auth.audience,
        )

    def test_missing_token_scope_is_denied_before_the_pep(self) -> None:
        server._CLAIMS.set(self.claims(scopes=[]))
        result = asyncio.run(server._authorized_call(server.SPECS["get_extension_inventory"]))
        self.assertIn("scope", result["error"].lower())
        self.assertEqual(self.pep.calls, 0)
        # SEC: a denial that never reaches Cedar still leaves a forensic record.
        self.assertEqual([record["reason"] for record in self.pep.rejections], ["scope_missing"])
        record = self.pep.rejections[0]
        self.assertEqual(record["tool"], "get_extension_inventory")
        self.assertEqual(record["principal_type"], "Client")
        self.assertEqual(record["realm"], "lab")
        self.assertIn("keycloak.extensions.read", record["detail"])
        self.assertIsNone(record["jti"])

    def test_unmapped_client_is_denied_and_audited(self) -> None:
        self.pep = _RecordingPep()
        server._RUNTIME = server.Runtime(config=self.mapped_config, pep=self.pep, admin=None)
        server._CLAIMS.set(self.claims(scopes=["keycloak.extensions.read"]))
        result = asyncio.run(server._authorized_call(server.SPECS["get_extension_inventory"]))
        self.assertIn("KC_MCP_CLIENT_ENTITY_MAP", result["error"])
        self.assertEqual(self.pep.calls, 0)
        self.assertEqual([record["reason"] for record in self.pep.rejections], ["client_unmapped"])
        self.assertEqual(self.pep.rejections[0]["principal_type"], "Client")
        self.assertEqual(
            self.pep.rejections[0]["principal"],
            "https://cimd.lab.local:8444/client-metadata.json",
        )

    def test_invalid_path_argument_is_denied_and_audited_without_the_value(self) -> None:
        server._CLAIMS.set(self.claims(scopes=["keycloak.extensions.read"]))
        result = asyncio.run(
            server._authorized_call(server.SPECS["get_extension_inventory"], realm="lab/../other")
        )
        self.assertIn("realm", result["error"])
        self.assertEqual(self.pep.calls, 0)
        self.assertEqual([record["reason"] for record in self.pep.rejections], ["path_invalid"])
        trail = str(self.pep.rejections)
        self.assertNotIn("lab/../other", trail, "the rejected value must not reach the audit log")
        self.assertNotIn("..", trail)
        self.assertEqual(self.pep.rejections[0]["realm"], "lab")

    def test_audit_failure_fails_closed_without_calling_the_pep(self) -> None:
        self.pep.audit_error = OSError("audit log is on a read-only mount")
        server._CLAIMS.set(self.claims(scopes=[]))
        result = asyncio.run(server._authorized_call(server.SPECS["get_extension_inventory"]))
        self.assertEqual(result["error"], "Authorization audit unavailable")
        self.assertEqual(self.pep.calls, 0)
        self.assertEqual(self.pep.rejections, [])

    def test_inventory_scope_reaches_the_pep(self) -> None:
        server._CLAIMS.set(self.claims(scopes=["keycloak.extensions.read"]))
        result = asyncio.run(server._authorized_call(server.SPECS["get_extension_inventory"]))
        self.assertEqual(self.pep.calls, 1)
        self.assertIn("Cedar denied", result["error"])

    def test_expired_stdio_token_is_rejected_before_policy_evaluation(self) -> None:
        claims = replace(self.claims(scopes=["keycloak.extensions.read"]), expires_at=1)
        with patch.object(server, "_STDIO_CLAIMS", claims), self.assertRaisesRegex(TokenError, "expired"):
            asyncio.run(server._authorized_call(server.SPECS["get_extension_inventory"]))
        self.assertEqual(self.pep.calls, 0)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
