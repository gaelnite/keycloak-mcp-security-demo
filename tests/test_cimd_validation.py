"""CIMD-01: allowlist entries validated against draft-ietf-oauth-client-id-metadata-document-03.

Offline tests (CI-safe): Section 3 grammar and Section 10.1 identifier-equality rules
applied to URL-form entries in KC_ALLOWED_CLIENT_IDS / KC_ALLOWED_CLIENT_IDS_FILE.
The live AS-side lifecycle behavior is characterized in tests/test_cimd_lifecycle.py.
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "mcp"))

try:
    from auth import KeycloakAuthConfig, TokenError, _cimd_entry  # noqa: E402

    HAVE_DEPS = True
except ImportError:  # pragma: no cover - bare system python lacks httpx/PyJWT
    HAVE_DEPS = False

ISSUER = "https://localhost:8443/realms/lab"
AUDIENCE = "https://localhost:8800/mcp"


def entry(value: str) -> str:
    return _cimd_entry(value, ISSUER, AUDIENCE)


@unittest.skipUnless(HAVE_DEPS, "httpx/PyJWT not installed (run under the lab venv)")
class CimdEntryGrammarTests(unittest.TestCase):
    """-03 Section 3: https scheme, required non-root path, banned components."""

    def test_valid_cimd_url_passes_through_unchanged(self) -> None:
        value = "https://cimd.lab.local:8444/client-metadata.json"
        self.assertEqual(entry(value), value)  # simple string, no normalization

    def test_native_client_id_passes_through(self) -> None:
        self.assertEqual(entry("mcp-gateway"), "mcp-gateway")

    def test_http_scheme_is_rejected(self) -> None:
        with self.assertRaises(TokenError):
            entry("http://localhost:9444/client-metadata.json")

    def test_uppercase_https_scheme_is_rejected(self) -> None:
        # Simple string comparison: an uppercase scheme can never match a
        # well-formed identifier and must not silently enter the allowlist.
        with self.assertRaises(TokenError):
            entry("HTTPS://localhost:9444/client-metadata.json")

    def test_non_https_url_scheme_is_rejected(self) -> None:
        with self.assertRaises(TokenError):
            entry("spiffe://lab.local/workload/mcp-client")

    def test_userinfo_is_rejected(self) -> None:
        with self.assertRaises(TokenError):
            entry("https://admin:***@localhost:9444/client-metadata.json")

    def test_query_is_rejected(self) -> None:
        # SHOULD NOT in -03; the RS refuses it outright (deny by default).
        with self.assertRaises(TokenError):
            entry("https://localhost:9444/client-metadata.json?cachebust=1")

    def test_fragment_is_rejected(self) -> None:
        with self.assertRaises(TokenError):
            entry("https://localhost:9444/client-metadata.json#x")

    def test_root_path_is_rejected(self) -> None:
        # -03 Section 3: MUST contain a path component other than "/".
        for value in ("https://localhost:9444/", "https://localhost:9444"):
            with self.assertRaises(TokenError, msg=value):
                entry(value)

    def test_dot_segments_are_rejected(self) -> None:
        for value in (
            "https://localhost:9444/../client-metadata.json",
            "https://localhost:9444/./client-metadata.json",
            "https://localhost:9444/keys/../client-metadata.json",
        ):
            with self.assertRaises(TokenError, msg=value):
                entry(value)

    def test_whitespace_and_backslash_are_rejected(self) -> None:
        for value in (
            "https://localhost:9444/client metadata.json",
            "https://localhost\\9444/client-metadata.json",
        ):
            with self.assertRaises(TokenError, msg=value):
                entry(value)


@unittest.skipUnless(HAVE_DEPS, "httpx/PyJWT not installed (run under the lab venv)")
class CimdEntryIdentifierEqualityTests(unittest.TestCase):
    """-03 Section 10.1: a Client Identifier URL must not be an AS/RS identifier."""

    def test_entry_equal_to_issuer_is_rejected(self) -> None:
        with self.assertRaises(TokenError):
            entry(ISSUER)

    def test_entry_equal_to_issuer_with_trailing_slash_is_rejected(self) -> None:
        with self.assertRaises(TokenError):
            entry(ISSUER + "/")

    def test_entry_equal_to_audience_is_rejected(self) -> None:
        with self.assertRaises(TokenError):
            entry(AUDIENCE)

    def test_subpath_of_issuer_is_allowed(self) -> None:
        # The draft bans identifier equality, not hosting location; a document
        # path below the issuer stays grammatically valid here. (Trust policy
        # for AS-hosted documents is the admission gate's job — SEC-02/SEC-02b.)
        self.assertEqual(entry(ISSUER + "/client-metadata.json"),
                         ISSUER + "/client-metadata.json")


@unittest.skipUnless(HAVE_DEPS, "httpx/PyJWT not installed (run under the lab venv)")
class FromEnvIntegrationTests(unittest.TestCase):

    def base_env(self) -> dict[str, str]:
        return {
            "KC_ISSUER": ISSUER,
            "KC_AUDIENCE": AUDIENCE,
            "KC_REALM": "lab",
            "KC_ALLOWED_CLIENT_IDS": "mcp-gateway https://localhost:9444/client-metadata.json",
        }

    def test_valid_mixed_entries_load(self) -> None:
        config = KeycloakAuthConfig.from_env(self.base_env())
        self.assertIn("mcp-gateway", config.allowed_client_ids)
        self.assertIn("https://localhost:9444/client-metadata.json", config.allowed_client_ids)

    def test_malformed_url_entry_fails_closed(self) -> None:
        env = self.base_env()
        env["KC_ALLOWED_CLIENT_IDS"] += " https://localhost:9444/"
        with self.assertRaises(TokenError):
            KeycloakAuthConfig.from_env(env)

    def test_issuer_equal_entry_in_file_fails_closed(self) -> None:
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write(ISSUER + "\n")
            path = fh.name
        try:
            env = self.base_env()
            env.pop("KC_ALLOWED_CLIENT_IDS")
            env["KC_ALLOWED_CLIENT_IDS_FILE"] = path
            with self.assertRaises(TokenError):
                KeycloakAuthConfig.from_env(env)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
