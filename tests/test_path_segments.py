"""SEC-05 (T17): Admin path-argument validation and check-then-use parity.

Crafted realm/user_id must never add a path segment, dot traversal,
query, or fragment to an Admin API URL, and Cedar/approval must see exactly
the value the URL uses. Needs the MCP SDK; skipped on bare Python.
"""

from __future__ import annotations

import asyncio
import sys
import unittest
from pathlib import Path
from urllib.parse import unquote

LAB = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(LAB / "mcp"))

try:
    import importlib.util

    HAVE_MCP = importlib.util.find_spec("mcp.server.fastmcp") is not None
except (ImportError, ValueError):  # pragma: no cover - depends on the interpreter
    HAVE_MCP = False

if HAVE_MCP:
    import server
    import tool_handlers
    from auth import TokenClaims
    from pep import Decision

CRAFTED = [
    "master/users/victim",          # extra segment: cross-realm subresource
    "lab/role-mappings/realm",      # extra segments: different endpoint
    "../../admin/realms/master",    # dot traversal
    "lab/../master",                # dot traversal inside
    ".",                            # self dot segment
    "..",                           # parent dot segment
    "lab?first=0",                  # query hijack
    "lab#frag",                     # fragment hijack
    "lab%2fusers%2fvictim",         # percent-encoded smuggle
    "lab\\..\\master",              # backslash traversal
    "lab\nx",                       # control character
]


class _RecordingAdmin:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    async def get(self, path, *, params=None):
        self.calls.append(("GET", path))
        return []

    async def post(self, path, payload):
        self.calls.append(("POST", path))
        return {}


class _AllowPep:
    def __init__(self) -> None:
        self.realms: list[str] = []
        self.rejections: list[dict] = []

    def authorize(self, spec, *, realm, **kwargs):
        self.realms.append(realm)
        return Decision("allow", reasons=("test-allow",))

    def audit_rejection(self, tool, principal_type, principal_id, realm, *, reason, detail,
                        approval_jti=None):
        self.rejections.append({"tool": tool.name, "principal_type": principal_type,
                                "realm": realm, "reason": reason, "detail": detail})


@unittest.skipUnless(HAVE_MCP, "the MCP SDK is required for server tests")
class PathSegmentUnitTests(unittest.TestCase):
    def test_valid_values_pass_through_unchanged(self):
        self.assertEqual(tool_handlers.path_segment("lab", field="realm"), "lab")
        uuid = "f47ac10b-58cc-4372-a567-0e02b2c3d479"
        self.assertEqual(tool_handlers.path_segment(uuid, field="user_id"), uuid)
        self.assertEqual(tool_handlers.path_segment("my.realm-1_2~x", field="realm"), "my.realm-1_2~x")

    def test_non_structural_characters_are_encoded_into_one_segment(self):
        encoded = tool_handlers.path_segment("foo bar", field="realm")
        self.assertEqual(encoded, "foo%20bar")
        self.assertEqual(unquote(encoded), "foo bar")

    def test_crafted_values_are_rejected(self):
        for value in CRAFTED:
            with self.subTest(value=value), self.assertRaises(tool_handlers.ValidationError):
                tool_handlers.path_segment(value, field="realm")

    def test_empty_non_string_and_oversized_are_rejected(self):
        for value in ("", None, 123, "x" * 256):
            with self.subTest(value=repr(value)[:30]), self.assertRaises(tool_handlers.ValidationError):
                tool_handlers.path_segment(value, field="realm")


@unittest.skipUnless(HAVE_MCP, "the MCP SDK is required for server tests")
class ImplInterpolationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.admin = _RecordingAdmin()

    def test_no_http_call_for_crafted_values(self):
        cases = [
            (tool_handlers.get_user, {"realm": "lab", "user_id": "123/credentials"}),
            (tool_handlers.get_user, {"realm": "lab/role-mappings", "user_id": "123"}),
            (tool_handlers.list_clients, {"realm": ".."}),
            (tool_handlers.list_users, {"realm": "lab?x=1"}),
        ]
        for impl, kwargs in cases:
            with self.subTest(impl=impl.__name__, **kwargs), self.assertRaises(tool_handlers.ValidationError):
                asyncio.run(impl(admin=self.admin, **kwargs))
        self.assertEqual(self.admin.calls, [])

    def test_valid_ids_produce_exactly_the_expected_segments(self):
        uuid = "f47ac10b-58cc-4372-a567-0e02b2c3d479"
        asyncio.run(tool_handlers.get_user(admin=self.admin, realm="lab", user_id=uuid))
        method, path = self.admin.calls[-1]
        self.assertEqual(method, "GET")
        self.assertEqual(path.split("/"), ["", "admin", "realms", "lab", "users", uuid])

    def test_get_client_crafted_realm_raises_before_lookup(self):
        with self.assertRaises(tool_handlers.ValidationError):
            asyncio.run(tool_handlers.get_client(admin=self.admin, realm="lab/../master", client_id="cli"))
        self.assertEqual(self.admin.calls, [])

    def test_get_client_resolved_uuid_used_as_single_segment(self):
        class _MatchAdmin:
            def __init__(self) -> None:
                self.paths: list[str] = []

            async def get(self, path, *, params=None):
                self.paths.append(path)
                if path.endswith("/clients"):
                    return [{"id": "cc8f2f6a-9b0f-4a3e-9e7e-6b7b8f9a0b1c"}]
                return {}

        admin = _MatchAdmin()
        asyncio.run(tool_handlers.get_client(admin=admin, realm="lab", client_id="cli"))
        self.assertEqual(
            admin.paths,
            [
                "/admin/realms/lab/clients",
                "/admin/realms/lab/clients/cc8f2f6a-9b0f-4a3e-9e7e-6b7b8f9a0b1c",
            ],
        )

    def test_get_client_rejects_unsafe_uuid_from_keycloak(self):
        class _OddAdmin:
            async def get(self, path, *, params=None):
                if path.endswith("/clients"):
                    return [{"id": "evil/../credentials"}]
                raise AssertionError("second request must not be issued")

        with self.assertRaises(tool_handlers.ValidationError):
            asyncio.run(tool_handlers.get_client(admin=_OddAdmin(), realm="lab", client_id="cli"))

@unittest.skipUnless(HAVE_MCP, "the MCP SDK is required for server tests")
class GateValidationTests(unittest.TestCase):
    """Crafted args must be rejected before approval and Cedar; clean args
    must reach the Admin URL as the same segment Cedar authorized."""

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
        self.pep = _AllowPep()
        self.admin = _RecordingAdmin()
        server._RUNTIME = server.Runtime(config=self.config, pep=self.pep, admin=self.admin)
        server._CLAIMS.set(
            TokenClaims(
                subject="alice",
                client_id="https://cimd.lab.local:8444/client-metadata.json",
                scopes=frozenset({"keycloak.users.read"}),
                realm="lab",
                admin=False,
                expires_at=9_999_999_999,
                issuer=self.config.auth.issuer,
                audience=self.config.auth.audience,
            )
        )

    def tearDown(self) -> None:
        server._RUNTIME = self._old_runtime
        server._CLAIMS.set(None)

    def test_crafted_realm_rejected_before_pep_and_http(self):
        result = asyncio.run(
            server._authorized_call(
                server.SPECS["get_user"], realm="master/users/victim",
                user_id="f47ac10b-58cc-4372-a567-0e02b2c3d479",
            )
        )
        self.assertIn("realm", result["error"])
        self.assertEqual(self.pep.realms, [])
        self.assertEqual(self.admin.calls, [])
        # T17's check-then-use gate now leaves a forensic record too.
        self.assertEqual([record["reason"] for record in self.pep.rejections], ["path_invalid"])
        record = self.pep.rejections[0]
        self.assertEqual(record["realm"], "lab", "the audit realm stays the authenticated one")
        self.assertIn("realm", record["detail"])
        self.assertNotIn("master/users/victim", str(self.pep.rejections))
        self.assertNotIn("victim", str(self.pep.rejections))

    def test_crafted_user_id_rejected_before_pep_and_http(self):
        result = asyncio.run(
            server._authorized_call(server.SPECS["get_user"], realm="lab", user_id="123/credentials")
        )
        self.assertIn("user_id", result["error"])
        self.assertEqual(self.pep.realms, [])
        self.assertEqual(self.admin.calls, [])
        self.assertEqual([record["reason"] for record in self.pep.rejections], ["path_invalid"])
        self.assertIn("user_id", self.pep.rejections[0]["detail"])
        self.assertNotIn("credentials", str(self.pep.rejections))

    def test_check_then_use_parity_for_clean_values(self):
        uuid = "f47ac10b-58cc-4372-a567-0e02b2c3d479"
        asyncio.run(server._authorized_call(server.SPECS["get_user"], realm="lab", user_id=uuid))
        self.assertEqual(self.pep.realms, ["lab"])
        self.assertEqual(len(self.admin.calls), 1)
        _, path = self.admin.calls[0]
        segments = path.split("/")
        self.assertEqual(segments, ["", "admin", "realms", "lab", "users", uuid])
        # the realm Cedar authorized is the exact segment the URL used
        self.assertEqual(unquote(segments[3]), self.pep.realms[-1])

    def test_parity_holds_for_needs_encoding_values(self):
        uuid = "f47ac10b-58cc-4372-a567-0e02b2c3d479"
        asyncio.run(server._authorized_call(server.SPECS["get_user"], realm="foo bar", user_id=uuid))
        self.assertEqual(self.pep.realms, ["foo bar"])
        _, path = self.admin.calls[0]
        self.assertEqual(unquote(path.split("/")[3]), self.pep.realms[-1])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
