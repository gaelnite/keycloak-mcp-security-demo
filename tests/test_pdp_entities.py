"""How the PDP builds the entity store for one decision.

The bundle's `cedar/entities.json` describes the tool surface. Everything about a caller
arrives per request from the PEP, built from verified token claims, and `mcp/pdp.mjs`
turns those claims into entities. These tests drive the real PDP over its stdin/stdout
pipe, because the question is what the PDP makes of a request - not what the PEP chose to
send, which `tests/test_policies.py` covers.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

LAB = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(LAB / "mcp"))

from pep import build_context  # noqa: E402

PDP_SCRIPT = LAB / "mcp" / "pdp.mjs"
BUNDLE = LAB / "cedar"

READ = {"type": "KeycloakMCP::Action", "id": "Read"}
LIST_USERS = {"type": "KeycloakMCP::Tool", "id": "list_users"}
INVENTORY = {"type": "KeycloakMCP::Tool", "id": "get_extension_inventory"}
GHOST = {"type": "KeycloakMCP::Tool", "id": "ghost_tool"}
USERS_READ = "keycloak.users.read"
EXTENSIONS_READ = "keycloak.extensions.read"


def user_attrs(scopes=(USERS_READ,), roles=("mcp-users-read",), **overrides) -> dict:
    attrs = {
        "subject": "runtime-user",
        "issuer": "https://keycloak.example/realms/lab",
        "clientId": "demo-desktop",
        "scopes": sorted(scopes),
        "roles": sorted(roles),
    }
    attrs.update(overrides)
    return attrs


def client_attrs(scopes=(EXTENSIONS_READ,), roles=(), **overrides) -> dict:
    attrs = {
        "clientId": "runtime-client",
        "scopes": sorted(scopes),
        "roles": sorted(roles),
    }
    attrs.update(overrides)
    return attrs


class PdpProcess:
    """The real PDP, one line in, one line out."""

    def __init__(self, entities: str | None = None) -> None:
        node = shutil.which("node")
        assert node is not None  # guarded by skipUnless at the class level
        if entities is None:
            self.directory = None
            script = PDP_SCRIPT
        else:
            # `mcp/pdp.mjs` loads `../cedar` relative to itself, so a request-specific
            # bundle means a private copy of the tree next to a private bundle.
            self.directory = tempfile.TemporaryDirectory()
            root = Path(self.directory.name)
            shutil.copytree(BUNDLE, root / "cedar")
            (root / "cedar" / "entities.json").write_text(entities)
            (root / "mcp").mkdir()
            script = root / "mcp" / "pdp.mjs"
            shutil.copy(PDP_SCRIPT, script)
            (script.parent / "node_modules").symlink_to(LAB / "mcp" / "node_modules")
        self.proc = subprocess.Popen(  # noqa: S603 - argv-list exec of shutil.which("node"), no shell
            [node, str(script)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            env={**os.environ, "ELECTRON_NO_ASAR": "1"},
        )

    def close(self) -> None:
        self.proc.stdin.close()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:  # pragma: no cover
            self.proc.kill()
        if self.directory is not None:
            self.directory.cleanup()

    def ask(self, **request) -> dict:
        request.setdefault("op", "authorize")
        request.setdefault("requestId", "probe")
        self.proc.stdin.write(json.dumps(request) + "\n")
        self.proc.stdin.flush()
        return json.loads(self.proc.stdout.readline())



class PdpAssertions(unittest.TestCase):
    """Assertions about PDP answers, shared by the store test cases."""

    pdp: PdpProcess

    def evaluate(self, tool=LIST_USERS, realm="lab", **request) -> dict:
        """Authorise one request and return the PDP answer, failing on any PDP error."""
        response = self.pdp.ask(
            action=READ,
            resource=tool,
            context=build_context(realm=realm, writes_enabled=False),
            **request,
        )
        self.assertTrue(response.get("ok"), response)
        return response

    def denies(self, response: dict, *policies: str) -> dict:
        """A denial must come from a named policy, never from a missing entity."""
        self.assertEqual(response["decision"], "deny", response)
        for policy in policies:
            self.assertIn(policy, response["determiningPolicies"], response)
        return response


@unittest.skipUnless(shutil.which("node"), "node is required for the entity store tests")
class PdpEntityStoreTests(PdpAssertions):
    @classmethod
    def setUpClass(cls) -> None:
        cls.pdp = PdpProcess()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.pdp.close()

    # --- the store holds the tool surface, nothing else ---------------------------
    def test_a_principal_without_facts_is_not_an_entity_and_denies(self) -> None:
        """Nothing in the bundle can authorise a caller on its own.

        A named principal that has no facts and was never seeded does not exist as an
        entity, so the request is denied with a Cedar diagnostic rather than falling back
        to some default identity.
        """
        response = self.pdp.ask(
            requestId="no-facts",
            principal={"type": "KeycloakMCP::Client", "id": "mcp-claude"},
            action=READ,
            resource=INVENTORY,
            context=build_context(realm="lab", writes_enabled=False),
        )
        self.assertTrue(response["ok"])
        self.assertEqual(response["decision"], "deny")
        self.assertIn("mcp-claude", json.dumps(response["errors"]))

    def test_an_unknown_tool_denies_and_does_not_crash(self) -> None:
        response = self.pdp.ask(
            requestId="ghost",
            principal={"type": "KeycloakMCP::Client", "id": "oidc:runtime-client"},
            client={"realm": "lab", "attrs": client_attrs()},
            action=READ,
            resource=GHOST,
            context=build_context(realm="lab", writes_enabled=False),
        )
        self.assertTrue(response["ok"])
        self.assertEqual(response["decision"], "deny")
        self.assertEqual(response["errors"], [])

    # --- principals live only in the request --------------------------------------
    def test_a_user_that_is_not_in_the_bundle_is_synthesised_with_its_realm(self) -> None:
        response = self.evaluate(
            principal={"type": "KeycloakMCP::User", "id": "oidc:runtime:subject-1"},
            user={"realm": "lab", "attrs": user_attrs()},
        )
        self.assertEqual(response["decision"], "allow")
        self.assertIn("kc-read-list-users", response["determiningPolicies"])

    def test_a_client_that_is_not_in_the_bundle_is_synthesised_with_its_realm(self) -> None:
        response = self.evaluate(
            principal={"type": "KeycloakMCP::Client", "id": "oidc:runtime-client"},
            client={"realm": "lab", "attrs": client_attrs()},
            tool=INVENTORY,
        )
        self.assertEqual(response["decision"], "allow")
        self.assertIn("kc-read-get-extension-inventory", response["determiningPolicies"])

    def test_machine_reads_require_the_realm_capability_role(self) -> None:
        cases = (
            ("no-role", (), "deny"),
            ("wrong-role", ("mcp-clients-read",), "deny"),
            ("authorised", ("mcp-users-read",), "allow"),
        )
        for subject, roles, expected in cases:
            with self.subTest(subject=subject):
                response = self.evaluate(
                    principal={
                        "type": "KeycloakMCP::Client",
                        "id": f"oidc:runtime:{subject}",
                    },
                    client={
                        "realm": "lab",
                        "attrs": client_attrs(scopes=(USERS_READ,), roles=roles),
                    },
                    tool=LIST_USERS,
                )
                self.assertEqual(response["errors"], [])
                self.assertEqual(response["decision"], expected)
                if expected == "allow":
                    self.assertIn("kc-read-list-users", response["determiningPolicies"])

    def test_authority_comes_from_the_request_attrs(self) -> None:
        cases = (
            ("no-scope", user_attrs(scopes=[]), "deny"),
            ("no-role", user_attrs(roles=[]), "deny"),
            ("unrelated-role", user_attrs(roles=["mcp-admin"]), "deny"),
            ("plain-user", user_attrs(roles=["user"], scopes=[USERS_READ]), "deny"),
            ("authorised", user_attrs(), "allow"),
        )
        for subject, attrs, expected in cases:
            with self.subTest(subject=subject):
                response = self.evaluate(
                    principal={"type": "KeycloakMCP::User", "id": f"oidc:runtime:{subject}"},
                    user={"realm": "lab", "attrs": attrs},
                )
                self.assertEqual(response["decision"], expected)

    def test_a_realm_that_was_never_seeded_exists_for_the_decision(self) -> None:
        """Cross-realm must evaluate to the deny policy, not to a missing-entity error.

        Neither realm entity is in the bundle: the caller's realm exists because the PEP
        sent it, and the realm being acted on is synthesised from the request context.
        Without the second one, `context.resource.realm` would not resolve and the request
        would fail as an evaluation error instead of `kc-deny-cross-realm`.
        """
        response = self.evaluate(
            principal={"type": "KeycloakMCP::User", "id": "oidc:runtime:cross-realm"},
            user={"realm": "runtime-a", "attrs": user_attrs()},
            realm="runtime-b",
        )
        self.denies(response, "kc-deny-cross-realm")

    def test_a_runtime_principal_in_its_own_unseeded_realm_is_allowed(self) -> None:
        response = self.evaluate(
            principal={"type": "KeycloakMCP::User", "id": "oidc:runtime:self-realm"},
            user={"realm": "runtime-c", "attrs": user_attrs()},
            realm="runtime-c",
        )
        self.assertEqual(response["decision"], "allow")

    # --- the request cannot redefine the bundle -----------------------------------
    def test_a_principal_with_facts_but_no_attrs_is_rejected(self) -> None:
        response = self.pdp.ask(
            requestId="no-attrs",
            principal={"type": "KeycloakMCP::User", "id": "oidc:runtime:no-attrs"},
            user={"realm": "lab"},
            action=READ,
            resource=LIST_USERS,
            context=build_context(realm="lab", writes_enabled=False),
        )
        self.assertFalse(response["ok"])
        self.assertIn("invalid dynamic principal", response["detail"])

    def test_a_principal_without_a_realm_is_rejected(self) -> None:
        response = self.pdp.ask(
            requestId="no-realm",
            principal={"type": "KeycloakMCP::User", "id": "oidc:runtime:no-realm"},
            user={"attrs": user_attrs()},
            action=READ,
            resource=LIST_USERS,
            context=build_context(realm="lab", writes_enabled=False),
        )
        self.assertFalse(response["ok"])
        self.assertIn("without a realm", response["detail"])

    def test_a_malformed_principal_uid_is_rejected(self) -> None:
        response = self.pdp.ask(
            requestId="bad-uid",
            principal={"type": "KeycloakMCP::User"},
            user={"realm": "lab", "attrs": user_attrs()},
            action=READ,
            resource=LIST_USERS,
            context=build_context(realm="lab", writes_enabled=False),
        )
        self.assertFalse(response["ok"])
        self.assertIn("invalid dynamic principal", response["detail"])

    def test_the_pdp_survives_a_rejected_request(self) -> None:
        """A bad request must not wedge the pipe: the next decision is still evaluated."""
        self.pdp.ask(requestId="bad", principal={"type": "KeycloakMCP::User", "id": "x"}, user={"realm": "lab"})
        response = self.evaluate(
            principal={"type": "KeycloakMCP::User", "id": "oidc:runtime:after-reject"},
            user={"realm": "lab", "attrs": user_attrs()},
        )
        self.assertEqual(response["decision"], "allow")


@unittest.skipUnless(shutil.which("node"), "node is required for the entity store tests")
class PdpStaticShadowTests(PdpAssertions):
    """A bundle that still carries principals must not be rewritable from the wire.

    The generated store has no principals, so the guard below is untestable against it.
    This fixture bundle is what the guard exists for: an operator who seeds a principal
    (or a test bundle that carries one) must not be able to have that principal's
    attributes redefined by the request being decided.
    """

    SEEDED = json.dumps(
        [
            {"uid": {"type": "KeycloakMCP::Realm", "id": "lab"}, "attrs": {}, "parents": []},
            {
                "uid": {"type": "KeycloakMCP::User", "id": "alice"},
                "attrs": user_attrs(subject="alice"),
                "parents": [{"__entity": {"type": "KeycloakMCP::Realm", "id": "lab"}}],
            },
            {
                "uid": {"type": "KeycloakMCP::Tool", "id": "list_users"},
                "attrs": {
                    "name": "list_users",
                    "requiredScope": USERS_READ,
                    "tier": "read",
                    "write": False,
                },
                "parents": [],
            },
            {
                "uid": {"type": "KeycloakMCP::Resource", "id": "realm:lab"},
                "attrs": {"kind": "realm", "realm": {"__entity": {"type": "KeycloakMCP::Realm", "id": "lab"}}},
                "parents": [],
            },
        ]
    )

    @classmethod
    def setUpClass(cls) -> None:
        cls.pdp = PdpProcess(entities=cls.SEEDED)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.pdp.close()

    def test_a_seeded_principal_is_still_decided_from_the_bundle_attrs(self) -> None:
        """A request with no facts is evaluated against the store as written."""
        response = self.evaluate(principal={"type": "KeycloakMCP::User", "id": "alice"})
        self.assertEqual(response["decision"], "allow")
        self.assertIn("kc-read-list-users", response["determiningPolicies"])

    def test_a_request_may_not_shadow_a_seeded_principal(self) -> None:
        """Same uid, different attrs: the request loses, because the bundle is the store."""
        response = self.pdp.ask(
            requestId="shadow",
            principal={"type": "KeycloakMCP::User", "id": "alice"},
            user={"realm": "lab", "attrs": user_attrs(subject="alice")},
            action=READ,
            resource=LIST_USERS,
            context=build_context(realm="lab", writes_enabled=False),
        )
        self.assertFalse(response["ok"])
        self.assertIn("shadows a static entity", response["detail"])

    def test_a_seeded_principal_cannot_act_in_a_realm_the_bundle_did_not_give_it(self) -> None:
        """A different target realm is a policy denial, not a rebind of the entity.

        The target realm is synthesised even for a principal that came from the store, so
        the answer is `kc-deny-cross-realm` rather than a missing-entity error: a caller's
        realm is whatever the bundle says it is, never whatever the request asked for.
        """
        response = self.evaluate(
            principal={"type": "KeycloakMCP::User", "id": "alice"},
            realm="runtime-only",
        )
        self.denies(response, "kc-deny-cross-realm")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
