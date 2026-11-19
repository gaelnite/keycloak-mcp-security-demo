"""SEC-02: CIMD admission must be gated, not open to any CA-capable process.

Pins the deny-by-default values in the realm policy/profile JSON and the lab
documents so a regression (e.g. re-adding 127.0.0.1 or widening the cache)
fails in CI without a live Keycloak. Mirrors docs/SECURITY.md T3/T4.
"""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
PROFILE = ROOT / "realm" / "cimd-profile.json"
POLICY = ROOT / "realm" / "cimd-policy.json"
PROFILE_J2 = ROOT / "ansible" / "playbooks" / "templates" / "cimd-profile.json.j2"
DOCS = [ROOT / "cimd" / name for name in ("client-metadata.json", "dynamic.json")]


def executor_config(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    profiles = data["profiles"] if isinstance(data, dict) else data
    for profile in profiles:
        for executor in profile.get("executors", []):
            if executor.get("executor") == "client-id-metadata-document":
                return executor["configuration"]
    raise AssertionError(f"no client-id-metadata-document executor in {path}")


class CimdAdmissionGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = executor_config(PROFILE)

    def test_permitted_domains_are_localhost_only(self) -> None:
        # Any 127.0.0.1 form is a bypass of the single dedicated name.
        self.assertEqual(self.config["cimd-allow-permitted-domains"], ["localhost"])

    def test_no_http_scheme(self) -> None:
        self.assertIs(self.config["cimd-allow-http-scheme"], False)

    def test_redirects_restricted_to_document_domain(self) -> None:
        self.assertIs(self.config["cimd-restrict-same-domain"], True)

    def test_cache_is_bounded(self) -> None:
        self.assertLessEqual(self.config["max-cache-time"], 3600)
        self.assertGreaterEqual(self.config["min-cache-time"], 300)

    def test_document_size_bounded(self) -> None:
        self.assertLessEqual(self.config["upper-limit-metadata-bytes"], 5000)

    def test_policy_condition_matches_profile_domains(self) -> None:
        policy = json.loads(POLICY.read_text(encoding="utf-8"))["policies"][0]
        self.assertTrue(policy["enabled"])
        for condition in policy["conditions"]:
            if condition["condition"] == "client-id-uri":
                configuration = condition["configuration"]
                self.assertEqual(configuration["client-id-uri-scheme"], ["https"])
                self.assertEqual(
                    configuration["client-id-uri-allow-permitted-domains"], ["localhost"]
                )
                return
        self.fail("client-id-uri condition missing")

    def test_ansible_template_stays_in_sync(self) -> None:
        # The Jinja template interpolates only the audience; every other gate
        # value must equal the realm JSON exactly.
        rendered = re.sub(r"\{\{[^}]*\}\}", "https://placeholder", PROFILE_J2.read_text(encoding="utf-8"))
        template_config = executor_config_from_text(rendered)
        realm_config = dict(self.config)
        audience = realm_config.pop("cimd-resource-indicator-allow-list")
        template_audience = template_config.pop("cimd-resource-indicator-allow-list")
        self.assertEqual(template_config, realm_config)
        self.assertEqual(audience, ["https://localhost:8800/mcp"])
        self.assertEqual(template_audience, ["https://placeholder"])

    def test_lab_documents_use_localhost_redirects(self) -> None:
        for path in DOCS:
            document = json.loads(path.read_text(encoding="utf-8"))
            host = urlparse(document["client_id"]).hostname
            for redirect in document["redirect_uris"]:
                self.assertEqual(
                    urlparse(redirect).hostname,
                    host,
                    f"{path.name}: redirect host must equal the document host (same-domain gate)",
                )


def executor_config_from_text(text: str) -> dict:
    data = json.loads(text)
    for profile in data["profiles"]:
        for executor in profile.get("executors", []):
            if executor.get("executor") == "client-id-metadata-document":
                return executor["configuration"]
    raise AssertionError("executor not found in template text")


if __name__ == "__main__":
    unittest.main()
