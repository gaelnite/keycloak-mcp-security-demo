"""Offline policy/PEP tests for the Keycloak MCP reference.

The PEP tests replace the PDP transport with a fake, so they need no Node. A second
class exercises the real Cedar bundle when Node + cedar-wasm are present; if they are
missing those tests skip rather than fail.

Run from lab/keycloak-mcp:
    python3 -m unittest discover -s tests -t .
    .venv/bin/python -m unittest discover -s tests -t .
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path

LAB = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(LAB / "mcp"))

import gen_cedar  # noqa: E402
import pep as pep_module  # noqa: E402
import tool_registry  # noqa: E402
from pep import CedarPep, ClientPrincipal, Decision, PdpError, PepError, UserPrincipal  # noqa: E402
from tool_registry import ADMIN, READ, TOOLS, TOOLS_BY_NAME, USER_LOCALE, USERS_READ, WRITE, ToolSpec  # noqa: E402

CEDAR = LAB / "cedar"
POLICIES = CEDAR / "policies.cedar"
ENTITIES = CEDAR / "entities.json"


ISSUER = "https://keycloak.example/realms/lab"
OTHER_ISSUER = "https://keycloak.example/realms/other"
ALL_SCOPES = frozenset(scope for tool in TOOLS for scope in tool.scopes)
READ_SCOPES = frozenset(tool.scopes[0] for tool in TOOLS if not tool.write)


def client_principal(scopes: frozenset[str] = READ_SCOPES, *, realm: str = "lab", admin: bool = False) -> ClientPrincipal:
    """A machine caller as its own token would describe it."""
    return ClientPrincipal(ISSUER, "mcp-client", realm, scopes, frozenset(), admin)


def user_principal(
    subject: str = "desktop-user",
    *,
    scopes: frozenset[str] = READ_SCOPES,
    roles: frozenset[str] = frozenset(),
    realm: str = "lab",
    admin: bool = False,
) -> UserPrincipal:
    """A human caller as its own token would describe it."""
    return UserPrincipal(ISSUER, subject, "desktop-client", realm, scopes, roles, admin)


def _tool(name: str) -> ToolSpec:
    return TOOLS_BY_NAME[name]


class RegistryTests(unittest.TestCase):
    def test_every_tool_declares_scope_policy_tier_extension(self) -> None:
        self.assertEqual(
            {tool.name for tool in TOOLS},
            {"get_extension_inventory", "list_users", "get_user", "list_clients", "get_client", "set_user_locale"},
        )
        names = [tool.name for tool in TOOLS]
        self.assertEqual(len(names), len(set(names)), "duplicate tool name")
        policy_ids = [tool.policy_id for tool in TOOLS]
        self.assertEqual(len(policy_ids), len(set(policy_ids)), "duplicate policy id")
        for tool in TOOLS:
            with self.subTest(tool=tool.name):
                self.assertTrue(tool.scopes)
                self.assertTrue(tool.policy_id.startswith("kc-"))
                self.assertIn(tool.tier, (READ, WRITE, ADMIN))
                self.assertIn(tool.extension, tool_registry.EXTENSIONS)
                self.assertEqual(tool.write, tool.tier == WRITE)

    def test_write_tools_are_explicitly_registered(self) -> None:
        writes = {tool.name for tool in TOOLS if tool.write}
        self.assertEqual(writes, {"set_user_locale"})
        for name in writes:
            self.assertEqual(_tool(name).tier, WRITE)

    def test_extension_filter_keeps_core_tools(self) -> None:
        visible = tool_registry.tools_for_extensions(frozenset({"orgs"}))
        names = {tool.name for tool in visible}
        self.assertEqual(names, set(TOOLS_BY_NAME))

    def test_read_and_admin_partitions(self) -> None:
        self.assertTrue(all(tool.tier == READ for tool in tool_registry.READ_TOOLS))
        self.assertTrue(all(tool.tier == ADMIN for tool in tool_registry.ADMIN_TOOLS))
        self.assertTrue(all(tool.tier == WRITE for tool in tool_registry.WRITE_TOOLS))


class CedarBundleTests(unittest.TestCase):
    def test_checked_in_bundle_matches_the_registry(self) -> None:
        self.assertEqual(POLICIES.read_text(), gen_cedar.render_policies())
        self.assertEqual(ENTITIES.read_text(), gen_cedar.render_entities())

    def test_every_tool_policy_id_exists_exactly_once(self) -> None:
        text = POLICIES.read_text()
        for tool in TOOLS:
            with self.subTest(tool=tool.name):
                self.assertEqual(
                    text.count(f'@id("{tool.policy_id}")'),
                    1,
                    f"missing or duplicate policy for {tool.name}",
                )

    def test_deny_by_default_and_required_forbids(self) -> None:
        text = POLICIES.read_text()
        for policy_id in (
            "kc-deny-unknown-tool",
            "kc-deny-cross-realm",
            "kc-deny-extension-missing",
            "kc-deny-writes-disabled",
            "kc-deny-unapproved-write",
        ):
            self.assertIn(f'@id("{policy_id}")', text)
        # Deny-by-default means there is no unconditional permit.
        self.assertNotIn("permit(principal, action, resource);", text)

    def test_write_policies_require_approval_and_enabled_writes(self) -> None:
        text = POLICIES.read_text()
        for tool in TOOLS:
            if not tool.write:
                continue
            start = text.index(f'@id("{tool.policy_id}")')
            end = text.index("};", start) + 2
            block = text[start:end]
            with self.subTest(tool=tool.name):
                self.assertIn("context.writesEnabled", block)
                self.assertIn("context.approvalVerified", block)
                self.assertIn("context.approvalTool == resource.name", block)
                self.assertIn("context.extensions.contains(resource.extension)", block)

    def test_policies_carry_no_secret_or_wildcard_permit(self) -> None:
        text = POLICIES.read_text()
        self.assertNotIn("password", text.lower())
        self.assertNotIn("secret", text.lower())
        self.assertNotIn("like ", text, "policies must not glob-match raw strings")

    def test_the_store_is_the_tool_surface_plus_realms(self) -> None:
        entities = json.loads(ENTITIES.read_text())
        by_type: dict[str, list[dict]] = {}
        for entity in entities:
            by_type.setdefault(entity["uid"]["type"], []).append(entity)
        self.assertEqual(
            set(by_type),
            {"KeycloakMCP::Realm", "KeycloakMCP::Tool", "KeycloakMCP::Resource"},
        )
        self.assertEqual({entity["uid"]["id"] for entity in by_type["KeycloakMCP::Realm"]}, set(gen_cedar.REALMS))
        self.assertEqual(
            {entity["uid"]["id"] for entity in by_type["KeycloakMCP::Tool"]},
            {tool.name for tool in TOOLS},
        )
        self.assertEqual(
            {entity["uid"]["id"] for entity in by_type["KeycloakMCP::Resource"]},
            {f"realm:{realm}" for realm in gen_cedar.REALMS},
        )
        for tool, entity in zip(TOOLS, by_type["KeycloakMCP::Tool"], strict=True):
            with self.subTest(tool=tool.name):
                self.assertEqual(entity["attrs"]["requiredScope"], tool.scopes[0])
                self.assertEqual(entity["attrs"]["tier"], tool.tier)
                self.assertEqual(entity["attrs"]["extension"], tool.extension)
                self.assertEqual(entity["attrs"]["write"], tool.write)

    def test_no_principal_is_seeded(self) -> None:
        """A caller is a runtime entity built from claims, so it must not be generatable.

        If a `User` or `Client` ever appears here it becomes a second source of
        authority, and regenerating the bundle would silently grant someone.
        """
        for entity in json.loads(ENTITIES.read_text()):
            self.assertNotIn(
                entity["uid"]["type"],
                {"KeycloakMCP::User", "KeycloakMCP::Client"},
                f"{entity['uid']['type']}::{entity['uid']['id']} must not be generated",
            )


class FakePdp:
    """Replaces CedarPep._request; records requests and returns a canned decision."""

    def __init__(self, *, decision: str = "allow", bundle_hash: str = "a" * 64) -> None:
        self.decision = decision
        self.bundle_hash = bundle_hash
        self.requests: list[dict] = []
        self.error: Exception | None = None

    def _request(self, payload: dict) -> dict:
        self.requests.append(payload)
        if self.error is not None:
            raise self.error
        return {
            "ok": True,
            "decision": self.decision,
            "determiningPolicies": [payload["resource"]["id"] and "kc-test-policy"],
            "errors": [],
            "bundleHash": self.bundle_hash,
        }


def make_pep(fake: FakePdp, audit_path: str | os.PathLike[str] | None = None) -> CedarPep:
    instance = CedarPep.__new__(CedarPep)
    instance.timeout = 0.5
    instance.audit_path = Path(audit_path) if audit_path else None
    instance._request = fake._request  # type: ignore[method-assign]
    return instance


class PepDecisionTests(unittest.TestCase):
    def test_allow_carries_policy_and_bundle_hash(self) -> None:
        fake = FakePdp()
        decision = make_pep(fake).authorize(
            _tool("get_extension_inventory"),
            principal=client_principal(),
            realm="lab",
            extensions=["orgs"],
        )
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reasons, ("kc-test-policy",))
        self.assertEqual(len(decision.bundle_hash), 64)
        request = fake.requests[0]
        self.assertEqual(request["action"]["id"], "Read")
        self.assertEqual(request["resource"]["id"], "get_extension_inventory")
        self.assertEqual(request["principal"]["id"], client_principal().id)

    def test_deny_is_returned_without_failing_closed(self) -> None:
        decision = make_pep(FakePdp(decision="deny")).authorize(
            _tool("get_extension_inventory"),
            principal=client_principal(),
            realm="lab",
            extensions=[],
        )
        self.assertFalse(decision.allowed)
        self.assertFalse(decision.failed_closed)

    def test_pdp_failure_fails_closed(self) -> None:
        fake = FakePdp()
        fake.error = PdpError("the Cedar PDP exceeded 500 ms")
        decision = make_pep(fake).authorize(
            _tool("get_extension_inventory"),
            principal=client_principal(),
            realm="lab",
            extensions=[],
        )
        self.assertFalse(decision.allowed)
        self.assertTrue(decision.failed_closed)
        self.assertEqual(decision.reasons, ("pdp_unavailable",))

    def test_audit_failure_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            blocker = Path(directory) / "not-a-directory"
            blocker.write_text("x")
            decision = make_pep(FakePdp(), audit_path=blocker / "audit.jsonl").authorize(
                _tool("get_extension_inventory"),
                principal=client_principal(),
                realm="lab",
                extensions=[],
            )
        self.assertFalse(decision.allowed)
        self.assertIn("audit_unavailable", decision.reasons)

    def test_context_maps_approval_expiry_and_extensions(self) -> None:
        fake = FakePdp()
        pep = make_pep(fake)
        pep.authorize(
            _tool("set_user_locale"),
            principal=client_principal(ALL_SCOPES, admin=True),
            realm="lab",
            extensions=["core"],
            writes_enabled=True,
            approval={"verified": True, "tool": "set_user_locale", "expiresIn": 0},
        )
        context = fake.requests[0]["context"]
        self.assertFalse(context["approvalVerified"])
        self.assertTrue(context["writesEnabled"])
        self.assertIn("core", context["extensions"])
        self.assertEqual(context["approvalTool"], "set_user_locale")

    def test_context_rejects_bad_approval_shape_without_crashing(self) -> None:
        fake = FakePdp()
        decision = make_pep(fake).authorize(
            _tool("set_user_locale"),
            principal=client_principal(ALL_SCOPES, admin=True),
            realm="lab",
            extensions=["core"],
            writes_enabled=True,
            approval={"verified": True, "tool": "other", "expiresIn": "soon"},
        )
        self.assertTrue(decision.allowed)  # fake PDP; approval mapping is what is tested
        self.assertFalse(fake.requests[0]["context"]["approvalVerified"])

    def test_audit_record_has_no_arguments_and_mode_0600(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            audit = Path(directory) / "authz.jsonl"
            make_pep(FakePdp(), audit_path=audit).authorize(
                _tool("get_extension_inventory"),
                principal=client_principal(),
                realm="lab",
                extensions=[],
            )
            text = audit.read_text()
            mode = stat.S_IMODE(os.stat(audit).st_mode)
        self.assertEqual(mode & 0o077, 0)
        record = json.loads(text.splitlines()[0])
        self.assertEqual(record["tool"], "get_extension_inventory")
        self.assertEqual(record["policyId"], "kc-read-get-extension-inventory")
        self.assertEqual(len(record["bundleHash"]), 64)
        self.assertNotIn("search", text)
        self.assertNotIn("realm=", text)

    def test_explicit_timeout_bounds_are_enforced(self) -> None:
        with self.assertRaises(PepError):
            CedarPep(timeout_ms=10)
        with self.assertRaises(PepError):
            CedarPep(timeout_ms=5000)

    def test_pep_from_env_rejects_non_integer_timeout(self) -> None:
        with self.assertRaises(PepError):
            pep_module.pep_from_env({"KC_CEDAR_TIMEOUT_MS": "soon"})


@unittest.skipUnless(shutil.which("node"), "Node is required for real Cedar checks")
class RealCedarTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.pep = CedarPep()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.pep.close()

    def authorize(self, tool: str, **kwargs: object):
        parameters = {
            "principal": client_principal(),
            "realm": "lab",
            "extensions": ["core"],
        }
        parameters.update(kwargs)
        return self.pep.authorize(_tool(tool), **parameters)  # type: ignore[arg-type]

    def test_real_read_allowed_in_realm(self) -> None:
        decision = self.authorize("get_extension_inventory")
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reasons, ("kc-read-get-extension-inventory",))

    def test_real_cross_realm_denied(self) -> None:
        decision = self.authorize("get_extension_inventory", realm="other")
        self.assertFalse(decision.allowed)
        self.assertIn("kc-deny-cross-realm", decision.reasons)

    def test_same_client_users_have_independent_role_and_scope_authority(self) -> None:
        helpdesk = user_principal("helpdesk-1", scopes=frozenset({USERS_READ.scope}), roles=frozenset({USERS_READ.role}))
        no_role = user_principal("reassigned-1", scopes=helpdesk.scopes, roles=frozenset())
        no_scope = user_principal(helpdesk.subject, scopes=frozenset(), roles=helpdesk.roles)
        self.assertNotEqual(helpdesk.id, no_role.id)
        self.assertEqual(helpdesk.id, no_scope.id)
        self.assertTrue(self.authorize("list_users", principal=helpdesk).allowed)
        self.assertFalse(self.authorize("list_users", principal=no_role).allowed)
        self.assertFalse(self.authorize("list_users", principal=no_scope).allowed)
        self.assertFalse(self.authorize("get_extension_inventory", principal=helpdesk).allowed)
        self.assertIn("kc-deny-cross-realm", self.authorize("list_users", realm="other", principal=helpdesk).reasons)

    def test_locale_scope_is_independent_and_approval_still_required(self) -> None:
        caller = user_principal("fixture", scopes=frozenset({USER_LOCALE.scope}), roles=frozenset({USER_LOCALE.role, USERS_READ.role}))
        approval = {"verified": True, "tool": "set_user_locale", "expiresIn": 60}
        self.assertFalse(self.authorize("list_users", principal=caller).allowed)
        self.assertFalse(self.authorize("set_user_locale", principal=caller, writes_enabled=True).allowed)
        self.assertTrue(self.authorize("set_user_locale", principal=caller, writes_enabled=True, approval=approval).allowed)

    def test_real_cedar_allow_with_an_evaluation_error_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            cedar = project / "cedar"
            mcp = project / "mcp"
            shutil.copytree(CEDAR, cedar)
            mcp.mkdir()
            pdp = mcp / "pdp.mjs"
            shutil.copy(LAB / "mcp" / "pdp.mjs", pdp)
            (mcp / "node_modules").symlink_to(LAB / "mcp" / "node_modules")
            with (cedar / "policies.cedar").open("a") as source:
                source.write('''
@id("kc-test-overflow")
permit(principal, action == KeycloakMCP::Action::"Read", resource == KeycloakMCP::Tool::"list_users")
when { 9223372036854775807 + 1 == 0 };
''')
            with CedarPep(pdp_script=pdp) as checker:
                decision = checker.authorize(
                    _tool("list_users"), principal=client_principal(READ_SCOPES | {USERS_READ.scope}), realm="lab", extensions=[],
                )
        self.assertFalse(decision.allowed)
        self.assertTrue(decision.failed_closed)
        self.assertIn("pdp_diagnostics", decision.reasons)

    def test_real_write_requires_enabled_and_approval(self) -> None:
        approval = {"verified": True, "tool": "set_user_locale", "expiresIn": 60}
        caller = user_principal("fixture", scopes=frozenset({USER_LOCALE.scope}), roles=frozenset({USER_LOCALE.role}))
        disabled = self.authorize("set_user_locale", principal=caller, writes_enabled=False, approval=approval)
        self.assertIn("kc-deny-writes-disabled", disabled.reasons)
        no_approval = self.authorize("set_user_locale", principal=caller, writes_enabled=True, approval=None)
        self.assertFalse(no_approval.allowed)
        approved = self.authorize("set_user_locale", principal=caller, writes_enabled=True, approval=approval)
        self.assertTrue(approved.allowed)
        self.assertIn("kc-write-set-user-locale", approved.reasons)

    def test_real_unknown_tool_denied(self) -> None:
        unknown = ToolSpec(
            name="delete_everything",
            description="not registered",
            scopes=("keycloak.users.manage",),
            policy_id="kc-read-delete-everything",
            tier=READ,
        )
        decision = self.pep.authorize(
            unknown,
            principal=client_principal(ALL_SCOPES, admin=True),
            realm="lab",
            extensions=[],
            tool_known=False,
        )
        self.assertFalse(decision.allowed)
        self.assertIn("kc-deny-unknown-tool", decision.reasons)

STUB_PREAMBLE = """
import fs from "node:fs";
import readline from "node:readline";
const counterPath = %r;
let count = fs.existsSync(counterPath) ? Number(fs.readFileSync(counterPath, "utf8")) : 0;
const answer = JSON.stringify({
  ok: true, decision: "allow", determiningPolicies: ["stub-allow"],
  bundleHash: "0".repeat(64),
}) + "\\n";
function bump() { count += 1; fs.writeFileSync(counterPath, String(count)); return count; }
const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
rl.on("line", (line) => {
  if (!line.trim()) return;
  const req = JSON.parse(line);
  if (req.op === "ping") {
    process.stdout.write(JSON.stringify({ ok: true, requestId: req.requestId }) + "\\n");
    return;
  }
  if (req.op === "authorize") {
"""

STUB_EPILOGUE = """    return;
  }
  process.stdout.write(JSON.stringify({ ok: false, requestId: req.requestId, error: "unknown_op" }) + "\\n");
});
"""

# Behaviour under test, keyed to the request counter: which attempt misbehaves
# and how. The PEP must deny that request once, then recover on the next.
STUB_CASES = {
    "slow_once": "    if (bump() === 1) setTimeout(() => process.stdout.write(answer), 2000);\n"
    "    else process.stdout.write(answer);\n",
    "partial_line": "    if (bump() === 1) {\n"
    "      process.stdout.write('{\"ok\":true, \"decis');\n"
    "      setTimeout(() => process.stdout.write('ion\":\"allow\"}\\n'), 3000);\n"
    "    } else process.stdout.write(answer);\n",
    "oversize": "    if (bump() === 1) process.stdout.write(\"x\".repeat(2 * 1024 * 1024));\n"
    "    else process.stdout.write(answer);\n",
    "trailing_bytes": "    if (bump() === 1) process.stdout.write(answer + answer);\n"
    "    else process.stdout.write(answer);\n",
    "exit_after_answer": "    bump();\n"
    "    process.stdout.write(answer, () => process.exit(0));\n",
    "always_slow": "    bump();\n    setTimeout(() => process.stdout.write(answer), 2000);\n",
}


class PdpRecoveryTests(unittest.TestCase):
    """Real Node stub PDP (no cedar-wasm): violations deny once, then recover.

    Covers T15: a >500 ms decision must not kill the PDP forever, and framing
    violations (partial line, oversize stream, trailing bytes, process exit)
    must deny fail-closed and restart under the bounded budget.
    """

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.counter = os.path.join(self.tmp.name, "count")

    def tearDown(self) -> None:
        if getattr(self, "pep", None):
            self.pep.close()
        self.tmp.cleanup()

    def make_pep(self, case: str) -> CedarPep:
        source = STUB_PREAMBLE + STUB_CASES[case] + STUB_EPILOGUE
        script = os.path.join(self.tmp.name, "stub.mjs")
        with open(script, "w", encoding="utf-8") as handle:
            handle.write(source % self.counter)
        self.pep = CedarPep(pdp_script=script, timeout_ms=500)
        return self.pep

    def authorize(self):
        return self.pep.authorize(
            _tool("get_extension_inventory"),
            principal=client_principal(),
            realm="lab",
            extensions=["core"],
        )

    def assert_denied(self, decision: Decision, needle: str) -> None:
        self.assertEqual(decision.decision, "deny")
        self.assertTrue(decision.failed_closed)
        self.assertEqual(decision.reasons, ("pdp_unavailable",))
        self.assertIn(needle, " ".join(decision.errors))

    def test_timeout_denies_once_then_recovers(self) -> None:
        self.make_pep("slow_once")
        self.assert_denied(self.authorize(), "exceeded 500 ms")
        recovered = self.authorize()
        self.assertTrue(recovered.allowed, msg=str(recovered.errors))
        self.assertEqual(recovered.reasons, ("stub-allow",))
        self.assertEqual(recovered.bundle_hash, "0" * 64)

    def test_partial_line_is_bounded_and_recovers(self) -> None:
        self.make_pep("partial_line")
        self.assert_denied(self.authorize(), "exceeded 500 ms")
        self.assertTrue(self.authorize().allowed)

    def test_oversized_response_denied_and_recovers(self) -> None:
        self.make_pep("oversize")
        self.assert_denied(self.authorize(), "1048576 bytes")
        self.assertTrue(self.authorize().allowed)

    def test_trailing_bytes_are_a_framing_violation(self) -> None:
        self.make_pep("trailing_bytes")
        self.assert_denied(self.authorize(), "trailing bytes")
        self.assertTrue(self.authorize().allowed)

    def test_unexpected_exit_respawns_lazily(self) -> None:
        pep = self.make_pep("exit_after_answer")
        first = self.authorize()
        self.assertTrue(first.allowed, msg=str(first.errors))
        # The stub exits right after answering; reap it so the death is visible
        # between requests. The next request must respawn and succeed. A death
        # that races with an in-flight request denies fail-closed once (EOF) and
        # the following request recovers, as test_timeout_denies_once_then_recovers
        # shows for the analogous kill path.
        pep._proc.wait(timeout=2)
        recovered = self.authorize()
        self.assertTrue(recovered.allowed, msg=str(recovered.errors))

    def test_flapping_pdp_backs_off_but_denies(self) -> None:
        self.make_pep("always_slow")
        last = None
        for _ in range(pep_module.MAX_RESTARTS_IN_WINDOW + 2):
            last = self.authorize()
            self.assertEqual(last.decision, "deny")
            self.assertTrue(last.failed_closed)
        self.assertIn("backing off", " ".join(last.errors))


if __name__ == "__main__":
    unittest.main()
