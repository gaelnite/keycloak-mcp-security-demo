"""CIMD-01: live-lab characterization of the AS's Client ID Metadata Document behavior.

Draft: draft-ietf-oauth-client-id-metadata-document-03 (read 2026-11-06).
Runs against the lab Keycloak on loopback and skips when it, the lab CA
material, or the admin bootstrap credentials are missing — CI stays offline-only.

Mechanics found empirically on Keycloak 26.8.1 (see docs/AUTHN-RESULTS.md):
admission happens when the AUTHORIZATION endpoint sees an unregistered CIMD
client_id matching the realm's cimd-policy (token-endpoint requests for unknown
clients get client_not_found without any fetch). Documents are served by a
throwaway HTTPS server on an ephemeral loopback port with the lab-CA-issued
certificate (SAN localhost), which the container trusts via KC_TRUSTSTORE_PATHS.

Every client created here is deleted in tearDownClass; failures are pinned as
expectedFailure only where the draft text is normative, with the section cited.
"""

from __future__ import annotations

import base64
import http.server
import importlib.util
import json
import os
import ssl
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KC = os.environ.get("KC", "https://localhost:8443")
REALM = os.environ.get("REALM", "lab")
ISSUER = f"{KC}/realms/{REALM}"
AUTHZ = f"{ISSUER}/protocol/openid-connect/auth"
TOKEN_URL = f"{ISSUER}/protocol/openid-connect/token"
CERTS = os.environ.get("CADIR", os.path.expanduser("~/.config/keycloak-mcp/certs"))
KC_ENV = os.environ.get("KC_ENV", os.path.expanduser("~/.config/keycloak-mcp/kc.env"))
CIMD_DIR = os.environ.get("SPIFFE_LAB_CIMD_DIR",
                          os.path.expanduser("~/.config/keycloak-mcp/cimd"))
KEY_FILE = os.path.join(CIMD_DIR, "keys", "lab.local", "ec-p256.pem")
CALLBACK = "http://localhost:8765/callback"

_spec = importlib.util.spec_from_file_location(
    "mint_svid_lab", os.path.join(REPO, "scripts", "mint-svid.py"))
mint = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mint)


def _admin_password() -> str | None:
    try:
        with open(KC_ENV, encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("KC_BOOTSTRAP_ADMIN_PASSWORD="):
                    return line.split("=", 1)[1].strip()
    except OSError:
        pass
    return None


def skip_reason() -> str | None:
    for path, why in ((os.path.join(CERTS, "ca.crt"), "lab CA"),
                      (os.path.join(CERTS, "server.crt"), "lab server cert"),
                      (os.path.join(CERTS, "server.key"), "lab server key"),
                      (KEY_FILE, "lab trust-domain key")):
        if not os.path.exists(path):
            return f"{why} missing ({path})"
    if _admin_password() is None:
        return "admin bootstrap credentials unavailable (kc.env)"
    ctx = ssl.create_default_context(cafile=os.path.join(CERTS, "ca.crt"))
    try:
        urllib.request.urlopen(AUTHZ, timeout=5, context=ctx)
    except urllib.error.HTTPError:
        return None
    except Exception as exc:
        return f"lab Keycloak not reachable: {exc}"
    return None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


_SKIP = skip_reason()


@unittest.skipIf(_SKIP is not None, _SKIP or "")
class CimdLifecycleTests(unittest.TestCase):
    """One test per normative rule probed; every admission probe creates + deletes."""

    @classmethod
    def setUpClass(cls) -> None:
        with open(KEY_FILE) as fh:
            d, x, y = (int(v, 16) for v in fh.read().split())
        cls.key_d, cls.kid = d, mint.kid_for((x, y))
        cls.jwks = {"keys": [{
            "kty": "EC", "crv": "P-256",
            "x": mint._b64u(x.to_bytes(32, "big")),
            "y": mint._b64u(y.to_bytes(32, "big")),
            "kid": cls.kid, "alg": "ES256", "use": "sig",
        }]}
        cls.docs: dict[str, tuple[int, str, bytes]] = {}
        cls.fetches: list[dict] = []
        outer = cls

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                outer.fetches.append({"path": self.path,
                                      "accept": self.headers.get("Accept")})
                doc = outer.docs.get(self.path.split("?", 1)[0])
                if doc is None:
                    self.send_error(404)
                    return
                status, ctype, body = doc
                self.send_response(status)
                if status in (301, 302, 303, 307, 308):
                    self.send_header("Location", body.decode())
                    self.end_headers()
                    return
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.port = cls.server.server_address[1]
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(os.path.join(CERTS, "server.crt"),
                            os.path.join(CERTS, "server.key"))
        cls.server.socket = ctx.wrap_socket(cls.server.socket, server_side=True)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

        cls.tls = ssl.create_default_context(cafile=os.path.join(CERTS, "ca.crt"))
        cls.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=cls.tls), _NoRedirect())
        pw = _admin_password()
        fields = urllib.parse.urlencode(
            {"client_id": "admin-cli", "username": "admin", "password": pw,
             "grant_type": "password"}).encode()
        req = urllib.request.Request(
            "https://localhost:8443/realms/master/protocol/openid-connect/token",
            data=fields, headers={"Content-Type": "application/x-www-form-urlencoded"})
        with urllib.request.urlopen(req, timeout=10, context=cls.tls) as resp:
            cls.admin_token = json.load(resp)["access_token"]

    @classmethod
    def tearDownClass(cls) -> None:
        if getattr(cls, "server", None) is None:
            return
        for client in cls._clients_for_port():
            cls._admin("DELETE", "clients/" + client["id"])
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    # -- helpers ---------------------------------------------------------------

    @classmethod
    def _clients_for_port(cls):
        req = urllib.request.Request(
            f"https://localhost:8443/admin/realms/{REALM}/clients",
            headers={"Authorization": f"Bearer {cls.admin_token}"})
        with urllib.request.urlopen(req, timeout=10, context=cls.tls) as resp:
            return [c for c in json.load(resp) if f":{cls.port}/" in c["clientId"]]

    @classmethod
    def _admin(cls, method, path):
        req = urllib.request.Request(
            f"https://localhost:8443/admin/realms/{REALM}/" + path,
            headers={"Authorization": f"Bearer {cls.admin_token}"}, method=method)
        try:
            with urllib.request.urlopen(req, timeout=10, context=cls.tls) as resp:
                raw = resp.read()
                return resp.status, (json.loads(raw) if raw else None)
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()[:300]

    def cid(self, name: str) -> str:
        return f"https://localhost:{self.port}/{name}"

    def document(self, name: str, body=None, ctype="application/json", status=200):
        raw = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.docs["/" + name] = (status, ctype, raw)
        return self.cid(name)

    def metadata(self, name: str, **overrides):
        doc = {"client_id": self.cid(name), "client_name": "CIMD-01 probe",
               "grant_types": ["authorization_code", "client_credentials"],
               "response_types": ["code"], "redirect_uris": [CALLBACK],
               "token_endpoint_auth_method": "private_key_jwt", "jwks": self.jwks}
        doc.update(overrides)
        for key, value in list(overrides.items()):
            if value is None:
                doc.pop(key, None)
        return doc

    def authorize(self, client_id: str) -> tuple[int, list[dict]]:
        query = urllib.parse.urlencode(
            {"client_id": client_id, "response_type": "code",
             "redirect_uri": CALLBACK, "scope": "openid", "state": "cimd01"})
        before = len(self.fetches)
        try:
            with self.opener.open(f"{AUTHZ}?{query}", timeout=15) as resp:
                resp.read()
                status = resp.status
        except urllib.error.HTTPError as exc:
            status = exc.code
        return status, self.fetches[before:]

    def token(self, **fields) -> tuple[int, dict]:
        req = urllib.request.Request(
            TOKEN_URL, data=urllib.parse.urlencode(fields).encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"})
        try:
            with self.opener.open(req, timeout=15) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            try:
                return exc.code, json.loads(raw or b"{}")
            except ValueError:
                return exc.code, {"raw": raw[:200].decode(errors="replace")}

    def client_assertion(self, client_id: str) -> str:
        now = int(time.time())
        payload = {"iss": client_id, "sub": client_id, "aud": TOKEN_URL,
                   "jti": f"cimd01-{time.time_ns()}", "iat": now, "exp": now + 120}
        header = mint._b64u(json.dumps(
            {"alg": "ES256", "kid": self.kid}, separators=(",", ":")).encode())
        body = mint._b64u(json.dumps(payload, separators=(",", ":")).encode())
        sig = mint._b64u(mint.sign_es256(f"{header}.{body}".encode(), self.key_d))
        return f"{header}.{body}.{sig}"

    # -- probes ----------------------------------------------------------------

    def test_s4_valid_document_is_fetched_and_admitted(self) -> None:
        url = self.document("admit.json", self.metadata("admit.json"))
        status, fetched = self.authorize(url)
        self.assertEqual(status, 200, "login page expected after admission")
        self.assertEqual([f["path"] for f in fetched], ["/admit.json"])
        clients = self._clients_for_port()
        self.assertEqual([c["clientId"] for c in clients], [url])
        self.assertFalse(clients[0]["publicClient"])
        self.assertEqual(clients[0]["clientAuthenticatorType"], "client-jwt")

    def test_s5_admitted_document_keys_verify_client_assertions(self) -> None:
        url = self.document("e2e.json", self.metadata("e2e.json"))
        status, _ = self.authorize(url)
        self.assertEqual(status, 200)
        code, body = self.token(
            grant_type="client_credentials", client_id=url,
            client_assertion=self.client_assertion(url),
            client_assertion_type="urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
        self.assertEqual(code, 200, body)
        self.assertIn("access_token", body)
        payload = body["access_token"].split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        self.assertEqual(claims.get("azp") or claims.get("client_id"), url)

    def test_s6_token_endpoint_does_not_fetch_unregistered(self) -> None:
        # -03 s6 auto-fetch is a SHOULD; Keycloak 26.8.1 admits only through
        # the authorization endpoint. A client_credentials request for an
        # unregistered CIMD client_id gets invalid_client WITHOUT any fetch,
        # and the same client_id is admitted on the authorization endpoint.
        url = self.document("cc-only.json", self.metadata("cc-only.json"))
        before = len(self.fetches)
        code, body = self.token(grant_type="client_credentials", client_id=url)
        self.assertIn(code, (400, 401))
        self.assertEqual(body.get("error"), "invalid_client", body)
        self.assertEqual(self.fetches[before:], [],
                         "no document fetch at the token endpoint (observed AS design)")
        status, fetched = self.authorize(url)
        self.assertEqual(status, 200, "authorization endpoint admits the same client")
        self.assertEqual([f["path"] for f in fetched], ["/cc-only.json"])

    def test_s4_client_id_mismatch_is_terminal(self) -> None:
        url = self.document("mismatch.json", self.metadata("mismatch.json",
                                                           client_id=self.cid("other.json")))
        status, _ = self.authorize(url)
        self.assertEqual(status, 400)
        self.assertNotIn(url, [c["clientId"] for c in self._clients_for_port()])

    def test_s41_jwks_and_jwks_uri_mutually_exclusive(self) -> None:
        url = self.document("both.json", self.metadata("both.json",
                                                       jwks_uri=f"https://localhost:{self.port}/j.json"))
        self.docs["/j.json"] = (200, "application/json", json.dumps(self.jwks).encode())
        status, _ = self.authorize(url)
        self.assertEqual(status, 400)
        self.assertNotIn(url, [c["clientId"] for c in self._clients_for_port()])

    def test_s5_document_without_key_material_rejected_for_pkj(self) -> None:
        url = self.document("nokeys.json", self.metadata("nokeys.json", jwks=None))
        status, _ = self.authorize(url)
        self.assertEqual(status, 400)

    def test_s5_secret_based_method_rejected(self) -> None:
        url = self.document("secret.json", self.metadata(
            "secret.json", token_endpoint_auth_method="client_secret_basic", jwks=None))
        status, _ = self.authorize(url)
        self.assertEqual(status, 400)
        self.assertNotIn(url, [c["clientId"] for c in self._clients_for_port()])

    def test_s5_absent_method_assumes_none_and_rejects_auth(self) -> None:
        url = self.document("absent.json", self.metadata(
            "absent.json", token_endpoint_auth_method=None, jwks=None))
        status, _ = self.authorize(url)
        self.assertEqual(status, 200)
        clients = [c for c in self._clients_for_port() if c["clientId"] == url]
        self.assertTrue(clients and clients[0]["publicClient"],
                        "-03 s5: absent method MUST be treated as none")
        code, body = self.token(
            grant_type="client_credentials", client_id=url,
            client_assertion=self.client_assertion(url),
            client_assertion_type="urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
        self.assertIn(code, (400, 401), f"auth against none MUST be rejected, got {code}")

    @unittest.expectedFailure
    def test_s5_rejection_of_none_client_uses_invalid_client_error(self) -> None:
        # -03 s5: "the authorization server MUST reject the request with
        # invalid_client". Keycloak 26.8.1 denies with error=unauthorized_client
        # (client_id present) instead — error-code deviation, logged as a gap.
        url = self.document("absent-ec.json", self.metadata(
            "absent-ec.json", token_endpoint_auth_method=None, jwks=None))
        self.authorize(url)
        code, body = self.token(
            grant_type="client_credentials", client_id=url,
            client_assertion=self.client_assertion(url),
            client_assertion_type="urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
        self.assertEqual(body.get("error"), "invalid_client", body)

    @unittest.expectedFailure
    def test_s44_client_uri_not_required_same_origin(self) -> None:
        # -03 s4.4: the AS "MUST NOT require that the client_uri be on the same
        # origin as, or a prefix of, the client_id or any of the redirect_uris".
        # With cimd-restrict-same-domain=true (PR #6 gate, deployed), Keycloak
        # 26.8.1 rejects documents whose informative client_uri is on another
        # domain ("Invalid Client ID: domain not allowed."). Config-level
        # candidate: keep restrict-same-domain but exempt informative URIs.
        url = self.document("uri.json", self.metadata(
            "uri.json", client_uri="https://example.org/app"))
        status, _ = self.authorize(url)
        self.assertEqual(status, 200)

    def test_s6_non_200_statuses_are_errors_and_redirects_not_followed(self) -> None:
        self.document("target.json", self.metadata("target.json"))
        self.docs["/redir.json"] = (302, "", f"https://localhost:{self.port}/target.json".encode())
        before = len(self.fetches)
        status, fetched = self.authorize(f"https://localhost:{self.port}/redir.json")
        self.assertEqual(status, 400)
        self.assertNotIn("/target.json", [f["path"] for f in fetched])
        # transient 503 then recovery on the same client id (error not cached)
        self.docs["/transient.json"] = (503, "application/json", b"{}")
        status503, _ = self.authorize(f"https://localhost:{self.port}/transient.json")
        self.assertEqual(status503, 400)
        self.docs["/transient.json"] = (200, "application/json",
                                        json.dumps(self.metadata("transient.json")).encode())
        status_ok, _ = self.authorize(f"https://localhost:{self.port}/transient.json")
        self.assertEqual(status_ok, 200, "s6.1: transient failure must not poison the client")

    def test_s62_min_cache_bounds_avoid_refetch(self) -> None:
        url = self.document("cached.json", self.metadata("cached.json"))
        status, _ = self.authorize(url)
        self.assertEqual(status, 200)
        self.docs["/cached.json"] = (404, "", b"gone")
        status2, fetched2 = self.authorize(url)
        self.assertEqual(status2, 200, "cached admission expected within min-cache-time")
        self.assertEqual(fetched2, [], "document must not be refetched inside min cache window")
        _, found = self._admin("GET", "clients?clientId=" + urllib.parse.quote(url, safe=""))
        expiry = found[0]["attributes"]["cimd.cache.expiry.time.in.sec"]
        remaining = int(expiry) - int(time.time())
        self.assertGreater(remaining, 240, "deployed min-cache-time is 300 s")

    @unittest.expectedFailure
    def test_s6_fetch_sends_accept_application_json(self) -> None:
        # -03 s6: "The Authorization Server SHOULD send an Accept header of
        # application/json when fetching the client metadata." Keycloak 26.8.1
        # sends no Accept header (Apache-HttpClient default) — recorded gap.
        url = self.document("accept.json", self.metadata("accept.json"))
        status, fetched = self.authorize(url)
        self.assertEqual(status, 200)
        self.assertTrue(fetched)
        self.assertEqual(fetched[0]["accept"], "application/json")

    def test_s1011_oversized_document_rejected(self) -> None:
        big = self.metadata("big.json")
        big["client_name"] = "A" * 6000  # deployed upper-limit-metadata-bytes=5000
        url = self.document("big.json", big)
        status, _ = self.authorize(url)
        self.assertEqual(status, 400)
        self.assertNotIn(url, [c["clientId"] for c in self._clients_for_port()])

    def test_s3_and_s101_identifier_urls_rejected_without_fetch(self) -> None:
        # client_id equal to the issuer (s10.1 confusion): the authorization
        # endpoint rejects before any document fetch.
        status, fetched = self.authorize(ISSUER)
        self.assertEqual(status, 400)
        self.assertEqual(fetched, [])


if __name__ == "__main__":
    unittest.main()
