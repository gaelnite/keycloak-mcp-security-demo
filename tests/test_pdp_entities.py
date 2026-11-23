"""How the PDP builds the entity store for one decision.

The bundle's `entities.json` is the policy-side view of the world. Everything about a
caller arrives per request from the PEP, built from verified token claims; a decision
must never depend on a principal somebody remembered to seed into the bundle. These
tests drive `mcp/pdp.mjs` directly, because the question is what the PDP makes of a
request, not what the PEP chose to send.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

LAB = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(LAB / "mcp"))

from pep import build_context  # noqa: E402

PDP = LAB / "mcp" / "pdp.mjs"

READ = {"type": "KeycloakMCP::Action", "id": "Read"}
LIST_USERS = {"type": "KeycloakMCP::Tool", "id": "list_users"}
INVENTORY = {"type": "KeycloakMCP::Tool", "id": "get_extension_inventory"}
GHOST = {"type": "KeycloakMCP::Tool", "id": "ghost_tool"}
USERS_READ = "keycloak.users.read"
EXTENSIONS_READ = "keycloak.extensions.read"


def user_attrs(scopes=("keycloak.users.read",), roles=("mcp-users-read",), admin=False, **overrides) -> dict:
    attrs = {
        "subject": "runtime-user",
        "issuer": "https://keycloak.example/realms/master",
        "clientId": "demo-desktop",
        "scopes": list(scopes),
        "roles": list(roles),
        "admin": admin,
    }
    attrs.update(overrides)
    return attrs


def client_attrs(scopes=("keycloak.extensions.read",), admin=False, **overrides) -> dict:
    attrs = {"clientId": "runtime-client", "scopes": list(scopes), "admin": admin}
    attrs.update(overrides)
    return attrs


@unittest.skipUnless(shutil.which("node"), "node is required for the entity store tests")
class PdpEntityStoreTests(unittest.TestCase):
    """Drives the real PDP over its stdin/stdout pipe."""

    @classmethod
    def setUpClass(cls) -> None:
        node = shutil.which("node")
        assert node is not None  # guarded by skipUnless; S101 is allowed in tests
        cls.proc = subprocess.Popen(  # noqa: S603 - argv-list exec of shutil.which("node"), no shell
            [node, str(PDP)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            env={**os.environ, "ELECTRON_NO_ASAR": "1"},
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.proc.stdin.close()
        try:
            cls.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:  # pragma: no cover
            cls.proc.kill()

    def ask(self, **request) -> dict:
        request.setdefault("op", "authorize")
        request.setdefault("requestId", "probe")
        self.proc.stdin.write(json.dumps(request) + "\n")
        self.proc.stdin.flush()
        return json.loads(self.proc.stdout.readline())

    def evaluate(self, tool=LIST_USERS, realm="master", **request) -> dict:
        """Authorise one request and return the PDP answer, failing on any PDP error."""
        response = self.ask(
            action=READ,
            resource=tool,
            context=build_context(realm=realm, extensions=["core"], writes_enabled=False),
            **request,
        )
        self.assertTrue(response.get("ok"), response)
        return response


    # --- the static store is still the fallback ---------------------------------
    def test_a_request_without_principal_facts_is_evaluated_against_the_bundle(self) -> None:
        response = self.evaluate(
            principal={"type": "KeycloakMCP::Client", "id": "mcp-claude"},
            tool=INVENTORY,
            realm="lab",
        )
        self.assertEqual(response["decision"], "allow")

    def test_an_unknown_tool_denies_with_a_cedar_diagnostic_and_does_not_crash(self) -> None:
        """A tool absent from the entity store is a deny, reported as a Cedar error."""
        response = self.ask(
            requestId="ghost",
            principal={"type": "KeycloakMCP::Client", "id": "mcp-claude"},
            action=READ,
            resource=GHOST,
            context=build_context(realm="lab", extensions=["core"], writes_enabled=False),
        )
        self.assertTrue(response["ok"])
        self.assertEqual(response["decision"], "deny")
        self.assertEqual(response["determiningPolicies"], [])
        self.assertIn("ghost_tool", json.dumps(response["errors"]))

    # --- principals live only in the request ------------------------------------
    def test_a_user_that_is_not_in_the_bundle_is_synthesised_with_its_realm(self) -> None:
        response = self.evaluate(
            principal={"type": "KeycloakMCP::User", "id": "oidc:desktop:subject-1"},
            user={"realm": "master", "attrs": user_attrs()},
        )
        self.assertEqual(response["decision"], "allow")
        self.assertIn("kc-read-list-users", response["determiningPolicies"])

    def test_a_client_that_is_not_in_the_bundle_is_synthesised_with_its_realm(self) -> None:
        response = self.evaluate(
            principal={"type": "KeycloakMCP::Client", "id": "oidc:runtime-client"},
            client={"realm": "lab", "attrs": client_attrs()},
            tool=INVENTORY,
            realm="lab",
        )
        self.assertEqual(response["decision"], "allow")
        self.assertIn("kc-read-get-extension-inventory", response["determiningPolicies"])

    def test_authority_comes_from_the_request_attrs_and_not_from_the_bundle(self) -> None:
        cases = (
            ("no-scope", user_attrs(scopes=[]), "deny"),
            ("no-role", user_attrs(roles=[]), "deny"),
            ("not-admin", user_attrs(admin=False, roles=["user"], scopes=["default-roles-master"]), "deny"),
            ("admin", user_attrs(roles=[], admin=True), "deny"),  # admin alone is not read authority
        )
        for subject, attrs, expected in cases:
            with self.subTest(subject=subject):
                response = self.evaluate(
                    principal={"type": "KeycloakMCP::User", "id": f"oidc:runtime:{subject}"},
                    user={"realm": "master", "attrs": attrs},
                )
                self.assertEqual(response["decision"], expected)

    def test_a_realm_that_was_never_seeded_exists_for_the_decision(self) -> None:
        """Cross-realm must evaluate to the deny policy, not to a missing-entity error.

        Neither realm entity here is in the bundle: the caller's realm exists because
        the PEP sent it, and the realm being acted on is synthesised from the request
        context. Without the second one, `context.resource.realm` would not resolve and
        the request would fail as an evaluation error instead of `kc-deny-cross-realm`.
        """
        response = self.evaluate(
            principal={"type": "KeycloakMCP::User", "id": "oidc:runtime:cross-realm"},
            user={"realm": "runtime-a", "attrs": user_attrs()},
            realm="runtime-b",
        )
        self.assertEqual(response["decision"], "deny")
        self.assertIn("kc-deny-cross-realm", response["determiningPolicies"])

    def test_a_runtime_principal_in_its_own_unseeded_realm_is_allowed(self) -> None:
        response = self.evaluate(
            principal={"type": "KeycloakMCP::User", "id": "oidc:runtime:self-realm"},
            user={"realm": "runtime-c", "attrs": user_attrs()},
            realm="runtime-c",
        )
        self.assertEqual(response["decision"], "allow")

    # --- the request cannot redefine the bundle ---------------------------------
    def test_a_request_may_not_shadow_a_static_entity(self) -> None:
        """`alice` is a static entity with her own attrs; a request cannot rewrite her."""
        response = self.ask(
            requestId="shadow",
            principal={"type": "KeycloakMCP::User", "id": "alice"},
            user={"realm": "master", "attrs": user_attrs(roles=["mcp-users-read"], admin=True)},
            action=READ,
            resource=LIST_USERS,
            context=build_context(realm="master", extensions=["core"], writes_enabled=False),
        )
        self.assertEqual(response["error"], "pdp_error")
        self.assertIn("shadows a static entity", response["detail"])

    def test_a_principal_with_facts_but_no_attrs_is_rejected(self) -> None:
        response = self.ask(
            requestId="no-attrs",
            principal={"type": "KeycloakMCP::User", "id": "oidc:runtime:no-attrs"},
            user={"realm": "master"},
            action=READ,
            resource=LIST_USERS,
            context=build_context(realm="master", extensions=["core"], writes_enabled=False),
        )
        self.assertEqual(response["error"], "pdp_error")
        self.assertIn("invalid dynamic principal", response["detail"])

    def test_a_principal_without_a_realm_is_rejected(self) -> None:
        response = self.ask(
            requestId="no-realm",
            principal={"type": "KeycloakMCP::User", "id": "oidc:runtime:no-realm"},
            user={"attrs": user_attrs()},
            action=READ,
            resource=LIST_USERS,
            context=build_context(realm="master", extensions=["core"], writes_enabled=False),
        )
        self.assertEqual(response["error"], "pdp_error")
        self.assertIn("realm", response["detail"])

    def test_a_malformed_principal_uid_is_rejected(self) -> None:
        response = self.ask(
            requestId="bad-uid",
            principal={"type": "KeycloakMCP::User"},
            user={"realm": "master", "attrs": user_attrs()},
            action=READ,
            resource=LIST_USERS,
            context=build_context(realm="master", extensions=["core"], writes_enabled=False),
        )
        self.assertEqual(response["error"], "pdp_error")

    def test_the_pdp_survives_a_rejected_request(self) -> None:
        """A bad request must not wedge the pipe: the next decision is still evaluated."""
        self.evaluate(
            principal={"type": "KeycloakMCP::User", "id": "oidc:runtime:before"},
            user={"realm": "master", "attrs": user_attrs()},
        )
        self.ask(requestId="bad", principal={"type": "KeycloakMCP::User", "id": "alice"}, user={"realm": "master"})
        response = self.evaluate(
            principal={"type": "KeycloakMCP::User", "id": "oidc:runtime:after"},
            user={"realm": "master", "attrs": user_attrs()},
        )
        self.assertEqual(response["decision"], "allow")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
