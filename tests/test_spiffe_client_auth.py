"""Live-lab negative cases for OAuth SPIFFE client authentication.

Draft: draft-ietf-oauth-spiffe-client-auth-03 (2026-11-02, read 2026-11-05).
These tests run against the lab Keycloak on loopback and skip when it
is not reachable, so CI stays offline-only. Each test maps to one normative
rule in draft -03 Sections 3.1/3.2/4/8.

Signing uses the lab trust-domain key read from the deployed CIMD tree
(default below, override SPIFFE_LAB_CIMD_DIR); nothing is written there.
The lab CA (override CADIR) must be available to verify the issuer.
"""

from __future__ import annotations

import base64
import importlib.util
import json
import os
import ssl
import tempfile
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KC = os.environ.get("KC", "https://localhost:8443")
REALM = os.environ.get("REALM", "lab")
ISSUER = f"{KC}/realms/{REALM}"
TOKEN_URL = f"{ISSUER}/protocol/openid-connect/token"
DISCOVERY = f"{ISSUER}/.well-known/openid-configuration"
CLIENT_ID = os.environ.get("CLIENT_ID", "https://localhost:9444/client-metadata.json")
SPIFFE_ID = os.environ.get("SPIFFE_ID", "spiffe://lab.local/workload/mcp-client")
TRUST_DOMAIN = "spiffe://lab.local"
CIMD_DIR = os.environ.get(
    "SPIFFE_LAB_CIMD_DIR", os.path.expanduser("~/.config/keycloak-mcp/cimd"))
KEY_FILE = os.path.join(CIMD_DIR, "keys", "lab.local", "ec-p256.pem")
CA_FILE = os.environ.get(
    "CADIR", os.path.expanduser("~/.config/keycloak-mcp/certs")) + "/ca.crt"
URN = "urn:ietf:params:oauth:client-assertion-type:jwt-spiffe"
WRONG_URN = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
OMIT = object()


def urlsafe_b64_pad(part: str) -> bytes:
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))

_spec = importlib.util.spec_from_file_location(
    "mint_svid_lab", os.path.join(REPO, "scripts", "mint-svid.py"))
mint = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mint)

def tls_context() -> ssl.SSLContext:
    return ssl.create_default_context(cafile=CA_FILE)


def lab_skip_reason() -> str | None:
    if not os.path.isfile(CA_FILE):
        return "lab CA missing (CADIR?)"
    if not os.path.exists(KEY_FILE):
        return "lab trust-domain key not present (SPIFFE_LAB_CIMD_DIR?)"
    try:
        urllib.request.urlopen(DISCOVERY, timeout=5, context=tls_context())
    except urllib.error.HTTPError:
        return None
    except Exception as exc:
        return f"lab Keycloak not reachable: {exc}"
    return None


_SKIP = lab_skip_reason()


@unittest.skipIf(_SKIP is not None, _SKIP or "")
class SpiffeClientAuthDraft03Tests(unittest.TestCase):
    """draft-ietf-oauth-spiffe-client-auth-03, live against the lab AS."""

    @classmethod
    def setUpClass(cls) -> None:
        with open(KEY_FILE) as fh:
            d, x, y = (int(v, 16) for v in fh.read().split())
        cls.d_val, cls.pub, cls.kid = d, (x, y), mint.kid_for((x, y))

    def build(self, key=None, kid=None, **claims):
        now = int(time.time())
        payload = {"sub": SPIFFE_ID, "aud": [ISSUER], "exp": now + 300, "iat": now}
        payload.update(claims)
        payload = {k: v for k, v in payload.items() if v is not OMIT}
        h = mint._b64u(json.dumps(
            {"alg": "ES256", "kid": kid or self.kid, "typ": "JWT"},
            separators=(",", ":")).encode())
        p = mint._b64u(json.dumps(payload, separators=(",", ":")).encode())
        si = (h + "." + p).encode()
        return h + "." + p + "." + mint._b64u(mint.sign_es256(si, key or self.d_val))

    def post(self, assertion, atype=URN, client_id=CLIENT_ID):
        fields = {"grant_type": "client_credentials",
                  "client_assertion": assertion, "client_assertion_type": atype}
        if client_id is not OMIT:
            fields["client_id"] = client_id
        req = urllib.request.Request(
            TOKEN_URL, data=urllib.parse.urlencode(fields).encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"})
        try:
            with urllib.request.urlopen(req, timeout=15, context=tls_context()) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read() or b"{}")

    def request(self, **claims):
        return self.post(self.build(**claims))

    def assert_denied(self, code, body, fragment=None):
        self.assertIn(code, (400, 401), f"expected rejection, got {code}: {body}")
        self.assertEqual(body.get("error"), "invalid_client", body)
        if fragment:
            self.assertIn(fragment, str(body.get("error_description", "")), body)

    def fresh_key(self):
        import shutil
        tmp = tempfile.mkdtemp(prefix="spiffe01-")
        self.addCleanup(shutil.rmtree, tmp, True)
        d, (x, y) = mint.init_key(tmp, TRUST_DOMAIN)
        return d, (x, y), mint.kid_for((x, y))

    # --- positive control --------------------------------------------------
    def test_positive_svid_gets_token(self):
        code, body = self.request()
        self.assertEqual(code, 200, body)
        claims = json.loads(urlsafe_b64_pad(body["access_token"].split(".")[1]))
        self.assertEqual(claims["azp"], CLIENT_ID)

    # --- s3.2 step 1: well-formed, required claims --------------------------
    def test_step1_missing_aud_claim_rejected(self):
        self.assert_denied(*self.request(aud=OMIT), fragment="audience")

    def test_step1_missing_exp_claim_rejected(self):
        self.assert_denied(*self.request(exp=OMIT), fragment="exp claim is required")

    # --- s3.2 step 2: expiry -------------------------------------------------
    def test_step2_expired_svid_rejected(self):
        now = int(time.time())
        self.assert_denied(*self.request(exp=now - 120, iat=now - 420),
                           fragment="not active")

    # --- s3.2 step 3: aud is the AS issuer identifier, as its SOLE value ----
    def test_step3_wrong_audience_rejected(self):
        self.assert_denied(*self.request(aud=["https://wrong.example"]),
                           fragment="Invalid token audience")

    def test_step3_aud_must_be_sole_issuer_value(self):
        self.assert_denied(*self.request(aud=[ISSUER, "https://extra.example"]),
                           fragment="Multiple audiences")

    # --- s3.2 step 4 + s6: signature via trust-domain keys only --------------
    def test_step4_unknown_kid_rejected(self):
        d, pub, kid = self.fresh_key()
        self.assert_denied(*self.post(self.build(key=d, kid=kid)))

    def test_step4_known_kid_signed_by_other_key_rejected(self):
        d, _, _ = self.fresh_key()
        self.assert_denied(*self.post(self.build(key=d)))

    # --- s3.2 step 5 + s3.1: SPIFFE ID must be authorized for the client -----
    def test_step5_sub_outside_trust_domain_rejected(self):
        self.assert_denied(*self.request(sub="spiffe://evil.local/workload/mcp-client"))

    def test_step5_sub_not_bound_to_client_rejected(self):
        self.assert_denied(*self.request(sub="spiffe://lab.local/workload/other"))

    def test_assertion_type_must_be_jwt_spiffe(self):
        self.assert_denied(*self.post(self.build(), atype=WRONG_URN))

    # --- s8.3: token confusion — an access token is not a JWT-SVID ----------
    def test_access_token_not_accepted_as_jwt_spiffe(self):
        _, body = self.request()
        self.assert_denied(*self.post(body["access_token"]))

    # --- s8.1: replay characterization (documents bearer behaviour) ---------
    def test_jwt_svid_is_replayable_until_expiry(self):
        """-03 s8.1: JWT-SVIDs are bearer credentials; jti uniqueness is not
        required of validators and SPIFFE implementations reuse cached SVIDs,
        so the AS accepts the same assertion twice. Mitigation here: 300 s
        mint TTL, TLS-only endpoint, SPIRE-01 rotation. Deployments needing
        replay resistance MUST track jti or use X509/WIT-SVID."""
        assertion = self.build(jti="spiffe01-fixed-jti")
        self.assertEqual(self.post(assertion)[0], 200)
        self.assertEqual(self.post(assertion)[0], 200,
                         "characterization of current AS behaviour")

    # --- draft MUSTs Keycloak 26.8.1 does not meet (upstream gaps) ----------
    @unittest.expectedFailure
    def test_s31_cimd_client_must_include_client_id(self):
        """-03 s3.1: clients identified by a CIMD MUST include client_id.
        Keycloak 26.8.1 (spiffe preview) issues the token anyway, keyed off
        the federated-jwt client attribute instead. XPASS here = fixed."""
        self.assert_denied(*self.post(self.build(), client_id=OMIT))

    @unittest.expectedFailure
    def test_s4_discovery_advertises_spiffe_jwt(self):
        """-03 s4: the AS MUST list spiffe_jwt in
        token_endpoint_auth_methods_supported. Keycloak 26.8.1 does not.
        XPASS here = fixed."""
        with urllib.request.urlopen(DISCOVERY, timeout=5, context=tls_context()) as r:
            methods = json.loads(r.read()).get(
                "token_endpoint_auth_methods_supported", [])
        self.assertIn("spiffe_jwt", methods)


if __name__ == "__main__":
    unittest.main()
