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
    from pep import ClientPrincipal, Decision, UserPrincipal


class _RecordingPep:
    def __init__(self) -> None:
        self.calls = 0
        self.last: dict = {}
        self.rejections: list[dict] = []
        self.audit_error: OSError | None = None

    def authorize(self, *args, **kwargs):
        self.calls += 1
        self.last = kwargs
        return Decision("deny", reasons=("test-deny",))

    def audit_rejection(self, tool, principal_type, principal_id, realm, *, reason, detail,
                        approval_jti=None, client_id=None):
        if self.audit_error is not None:
            raise self.audit_error
        self.rejections.append({"tool": tool.name, "principal_type": principal_type,
                                "principal": principal_id, "realm": realm, "reason": reason,
                                "detail": detail, "jti": approval_jti, "client_id": client_id})


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

    def setUp(self) -> None:
        self._old_runtime = server._RUNTIME
        self.pep = _RecordingPep()
        server._RUNTIME = server.Runtime(config=self.config, pep=self.pep, admin=None)

    def tearDown(self) -> None:
        server._RUNTIME = self._old_runtime
        server._CLAIMS.set(None)

    def claims(
        self,
        *,
        scopes,
        admin=False,
        roles=frozenset(),
        realm_roles=frozenset(),
        interactive=False,
        client_id=None,
    ) -> TokenClaims:
        return TokenClaims(
            subject="alice",
            client_id=client_id or "https://cimd.lab.local:8444/client-metadata.json",
            scopes=frozenset(scopes),
            realm="lab",
            admin=admin,
            expires_at=9_999_999_999,
            issuer=self.config.auth.issuer,
            audience=self.config.auth.audience,
            roles=frozenset(roles),
            realm_roles=frozenset(realm_roles),
            interactive=interactive,
        )

    def test_a_human_principal_carries_keycloak_roles_not_mcp_capabilities(self) -> None:
        """`realm_access.roles` decide policy; `mcp_roles` decides what is offered.

        The demo grants a helpdesk user `mcp-users-read` through a group and its tool
        capability through a consented client scope. Confusing the two claims either
        widens policy to whatever a token was consented for, or - as first written -
        leaves every human with no Cedar roles at all and denies the read the demo
        advertises.
        """
        claims = TokenClaims(
            subject="demo-helpdesk",
            client_id="mcp-desktop",
            scopes=frozenset({"keycloak.users.read"}),
            realm="lab",
            admin=False,
            expires_at=9_999_999_999,
            issuer=self.config.auth.issuer,
            audience=self.config.auth.audience,
            roles=frozenset({"mcp-users-read"}),  # the `mcp_roles` capability claim
            realm_roles=frozenset(),              # the group-given realm role, below
            interactive=True,
        )
        self.assertTrue(claims.interactive)
        self.assertEqual(server.principal_for(claims).roles, frozenset())
        granted = replace(claims, realm_roles=frozenset({"mcp-users-read"}))
        principal = server.principal_for(granted)
        self.assertIsInstance(principal, UserPrincipal)
        self.assertEqual(principal.roles, frozenset({"mcp-users-read"}))
        self.assertFalse(principal.admin)

    def test_a_pre_cedar_denial_names_the_client_behind_the_principal(self) -> None:
        server._CLAIMS.set(self.claims(scopes=[], client_id="mcp-desktop"))
        asyncio.run(server._authorized_call(server.SPECS["list_users"]))
        rejection = self.pep.rejections[-1]
        self.assertEqual(rejection["reason"], "scope_missing")
        self.assertEqual(rejection["client_id"], "mcp-desktop")

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

    def test_a_machine_client_is_authorised_on_its_own_token(self) -> None:
        """There is no client-to-entity map: the verified token is the principal.

        The client id reaches Cedar as a runtime entity carrying the token's own scopes,
        so an allowlisted client is judged by policy instead of by whether somebody
        remembered to map it, and no seeded fixture can lend it authority it does not have.
        """
        client_id = "https://other.lab.local/client-metadata.json"
        scopes = frozenset({"keycloak.extensions.read"})
        server._CLAIMS.set(self.claims(scopes=scopes, client_id=client_id))
        result = asyncio.run(server._authorized_call(server.SPECS["get_extension_inventory"]))
        self.assertEqual(self.pep.calls, 1)
        principal = self.pep.last["principal"]
        self.assertEqual(principal.entity_type, "Client")
        self.assertEqual(
            principal.id,
            ClientPrincipal(self.config.auth.issuer, client_id, "lab", scopes, frozenset()).id,
        )
        self.assertEqual(principal.scopes, scopes)
        self.assertIn("Cedar denied", result["error"])

    def test_a_human_token_is_authorised_as_its_subject(self) -> None:
        """An interactive token reaches Cedar as the human, with Keycloak's own roles.

        `mcp_roles` decides which tools the server even offers (the entitlement gate
        above the PEP); `realm_access.roles` is what Cedar sees, so a client-side claim
        cannot impersonate a Keycloak role assignment.
        """
        server._CLAIMS.set(
            self.claims(
                scopes=["keycloak.users.read"],
                roles=["mcp-users-read"],
                realm_roles=["mcp-users-read"],
                interactive=True,
            )
        )
        asyncio.run(server._authorized_call(server.SPECS["list_users"]))
        principal = self.pep.last["principal"]
        self.assertEqual(principal.entity_type, "User")
        self.assertEqual(principal.roles, frozenset({"mcp-users-read"}))
        self.assertEqual(
            principal.id,
            UserPrincipal(
                self.config.auth.issuer, "alice", principal.client_id, "lab",
                frozenset({"keycloak.users.read"}), frozenset({"mcp-users-read"}),
            ).id,
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
