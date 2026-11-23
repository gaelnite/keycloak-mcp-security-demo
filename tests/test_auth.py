"""Keycloak token-verification tests (need the server venv: PyJWT + cryptography).

These are skipped under a bare system Python that lacks PyJWT; the required offline
policy suite is tests/test_policies.py.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import ssl
import sys
import tempfile
import time
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest import mock

LAB = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(LAB / "mcp"))

try:
    import httpx
    import jwt
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    HAVE_CRYPTO = True
except ImportError:  # pragma: no cover - depends on the interpreter
    HAVE_CRYPTO = False

if HAVE_CRYPTO:
    import auth
    from auth import (
        JwksCache,
        KeycloakAuthConfig,
        KeycloakTokenVerifier,
        TokenError,
    )
    from tool_registry import CLIENTS_READ, USERS_READ

ISSUER = "https://kc.lab.example/realms/lab"
CLIENT_URL = "https://clients.example/claude.json"
JWKS_URL = ISSUER + "/protocol/openid-connect/certs"


class _FakeJwks:
    def __init__(self, public_key):
        self.public_key = public_key

    async def get_key(self, kid: str):
        if kid != "k1":
            raise TokenError("unknown key id")
        return self.public_key


@unittest.skipUnless(HAVE_CRYPTO, "PyJWT + cryptography are required")
class TokenVerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.public_key = cls.private_key.public_key()
        cls.config = KeycloakAuthConfig.from_env(
            {
                "KC_ISSUER": ISSUER,
                "KC_AUDIENCE": "keycloak-mcp",
                "KC_ALLOWED_CLIENT_IDS": f"{CLIENT_URL} mcp-cursor",
            }
        )
        cls.verifier = KeycloakTokenVerifier(cls.config, jwks=_FakeJwks(cls.public_key))

    def token(self, **overrides):
        now = int(time.time())
        claims = {
            "iss": ISSUER,
            "aud": "keycloak-mcp",
            "sub": "user-1",
            "iat": now,
            "exp": now + 300,
            "azp": CLIENT_URL,
            "scope": "keycloak.realms.read keycloak.users.read",
            "realm_access": {"roles": ["mcp-admin"]},
        }
        claims.update(overrides)
        return jwt.encode(claims, self.private_key, algorithm="RS256", headers={"kid": "k1"})

    def verify(self, token: str):
        return asyncio.run(self.verifier.verify(token))

    def test_valid_token_yields_claims_and_scopes(self) -> None:
        claims = self.verify(self.token())
        self.assertEqual(claims.subject, "user-1")
        self.assertEqual(claims.client_id, CLIENT_URL)
        self.assertEqual(claims.realm, "lab")
        self.assertTrue(claims.admin)
        self.assertIn("keycloak.realms.read", claims.scopes)
        self.assertTrue(claims.allows("keycloak.users.read"))

    def test_interactive_token_class_and_capability_audience_are_bound(self) -> None:
        resource = "https://mcp.example/mcp"
        config = KeycloakAuthConfig.from_env({
            "KC_ISSUER": ISSUER,
            "KC_MCP_RESOURCE_URL": resource,
            "KC_ALLOWED_CLIENT_IDS": CLIENT_URL,
            "KC_MCP_INTERACTIVE_CLIENT_IDS": CLIENT_URL,
        })
        verifier = KeycloakTokenVerifier(config, jwks=_FakeJwks(self.public_key))
        payload = {
            "aud": [resource, USERS_READ.requester_audience(resource)],
            "typ": "Bearer",
            "scope": USERS_READ.scope,
            "mcp_roles": [USERS_READ.role],
        }
        claims = asyncio.run(verifier.verify(self.token(**payload)))
        self.assertTrue(claims.interactive)
        self.assertFalse(claims.admin)
        self.assertEqual(claims.roles, {USERS_READ.role})
        for changes in (
            {"typ": "ID"},
            {"typ": None},
            {"mcp_roles": USERS_READ.role},
            {"aud": resource},
            {"aud": [*payload["aud"], "https://admin.example/admin/realms/lab"]},
            {"aud": [*payload["aud"], CLIENTS_READ.requester_audience(resource)]},
        ):
            with self.subTest(changes=changes), self.assertRaises(TokenError):
                asyncio.run(verifier.verify(self.token(**{**payload, **changes})))

    def test_cimd_url_allowlist_is_exact(self) -> None:
        with self.assertRaises(TokenError) as caught:
            self.verify(self.token(azp=CLIENT_URL + "/"))
        self.assertIn("allowlisted", str(caught.exception))

    def test_client_id_claim_is_accepted_when_azp_is_absent(self) -> None:
        token = self.token()
        # Re-encode without azp but with client_id.
        decoder = jwt.decode(token, options={"verify_signature": False})
        decoder.pop("azp")
        decoder["client_id"] = "mcp-cursor"
        signed = jwt.encode(decoder, self.private_key, algorithm="RS256", headers={"kid": "k1"})
        self.assertEqual(self.verify(signed).client_id, "mcp-cursor")

    def test_wrong_audience_is_rejected(self) -> None:
        with self.assertRaises(TokenError):
            self.verify(self.token(aud="some-other-api"))

    def test_expired_token_is_rejected(self) -> None:
        with self.assertRaises(TokenError):
            self.verify(self.token(exp=int(time.time()) - 120))

    def test_wrong_issuer_is_rejected(self) -> None:
        with self.assertRaises(TokenError):
            self.verify(self.token(iss="https://evil.example/realms/lab"))

    def test_unknown_algorithm_is_rejected(self) -> None:
        token = jwt.encode({"iss": ISSUER}, "x" * 40, algorithm="HS256", headers={"kid": "k1"})
        with self.assertRaises(TokenError):
            self.verify(token)

    def test_scp_list_is_parsed(self) -> None:
        token = self.token(scope=None, scp=["keycloak.realms.read", "keycloak.groups.read"])
        claims = self.verify(token)
        self.assertEqual(claims.scopes, frozenset({"keycloak.realms.read", "keycloak.groups.read"}))

    def test_config_requires_an_allowlist(self) -> None:
        with self.assertRaises(TokenError):
            KeycloakAuthConfig.from_env(
                {"KC_ISSUER": ISSUER, "KC_AUDIENCE": "keycloak-mcp"}
            )

    def test_allowlist_file_keeps_a_comma_inside_a_url(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "clients.txt"
            path.write_text("https://clients.example/cb,state=1\n")
            config = KeycloakAuthConfig.from_env(
                {
                    "KC_ISSUER": ISSUER,
                    "KC_AUDIENCE": "keycloak-mcp",
                    "KC_ALLOWED_CLIENT_IDS_FILE": str(path),
                }
            )
        self.assertEqual(
            config.allowed_client_ids, frozenset({"https://clients.example/cb,state=1"})
        )


class _EndlessStream(httpx.AsyncByteStream):
    """A body that never ends and declares no length: only a running count stops it.

    `bytes` for the sync path, `__aiter__` for the async one; `served` proves the
    client stopped reading at the cap instead of buffering the whole document.
    """

    def __init__(self, chunk: bytes, chunks: int) -> None:
        self.chunk = chunk
        self.chunks = chunks
        self.served = 0

    async def __aiter__(self):
        for index in range(self.chunks):
            self.served = index + 1
            yield self.chunk


def _jwks_document(public_key) -> bytes:
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(public_key))
    jwk.update({"kid": "k1", "alg": "RS256", "use": "sig"})
    return json.dumps({"keys": [jwk]}).encode()


@unittest.skipUnless(HAVE_CRYPTO, "httpx + PyJWT + cryptography are required")
class JwksFetchTests(unittest.TestCase):
    """The JWKS fetch must be bounded while streaming, and never leave the host."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.public_key = cls.private_key.public_key()
        cls.document = _jwks_document(cls.public_key)

    def cache(self, handler, **kwargs) -> JwksCache:
        return JwksCache(JWKS_URL, transport=httpx.MockTransport(handler), **kwargs)

    def refresh(self, cache: JwksCache) -> None:
        asyncio.run(cache.refresh())

    def test_bound_is_one_source_and_smaller_than_a_token_cache_buster(self) -> None:
        # The plan calls for a single assertable source of truth. MAX_JWKS_BYTES is
        # that constant: the default of JwksCache(max_bytes=...) and the streaming
        # read both derive from it.
        self.assertEqual(auth.MAX_JWKS_BYTES, 256 * 1024)
        self.assertEqual(
            self.cache(lambda request: httpx.Response(200, content=b"{}"))._max_bytes,
            auth.MAX_JWKS_BYTES,
        )

    def test_max_bytes_must_be_positive(self) -> None:
        with self.assertRaises(ValueError):
            self.cache(lambda request: httpx.Response(200, content=b"{}"), max_bytes=0)

    def test_oversize_declared_content_length_is_refused(self) -> None:
        cache = self.cache(
            lambda request: httpx.Response(
                200, headers={"content-length": str(auth.MAX_JWKS_BYTES + 1)}, stream=_EndlessStream(b"x", 1)
            ),
            max_bytes=1024,
        )
        with self.assertRaises(TokenError) as caught:
            self.refresh(cache)
        self.assertIn("large", str(caught.exception))

    def test_oversize_streamed_body_is_refused_without_buffering_it(self) -> None:
        # 4 MiB of unannounced chunks against a 64 KiB cap. The old `response.content`
        # read buffered all 4 MiB before checking anything; a streaming bound must stop
        # within one read chunk of the cap.
        stream = _EndlessStream(b"x" * 4096, 1024)
        cache = self.cache(
            lambda request: httpx.Response(200, stream=stream), max_bytes=64 * 1024
        )
        with self.assertRaises(TokenError):
            self.refresh(cache)
        self.assertLessEqual(
            stream.served * 4096, 64 * 1024 + auth.JWKS_CHUNK_BYTES
        )

    def test_previous_keys_survive_an_oversize_refresh(self) -> None:
        mode = {"oversize": False}

        def handler(request):
            if mode["oversize"]:
                return httpx.Response(200, stream=_EndlessStream(b"y" * 8192, 1024))
            return httpx.Response(200, content=self.document)

        cache = self.cache(handler, max_bytes=64 * 1024)
        self.refresh(cache)
        self.assertEqual(sorted(cache._keys), ["k1"])
        mode["oversize"] = True
        with self.assertRaises(TokenError):
            self.refresh(cache)
        # A failed refresh must never widen or corrupt access: the keys that were
        # verified before the attack are still the keys in use.
        self.assertEqual(sorted(cache._keys), ["k1"])
        claims = asyncio.run(cache.get_key("k1"))
        self.assertEqual(claims.key_id, "k1")



    def test_fetch_does_not_inherit_an_ambient_proxy(self) -> None:
        # A proxy picked up from the environment would put a third party between the
        # MCP server and its issuer. MockTransport cannot show a proxy being used, so
        # assert the two things httpx actually acts on: trust_env and the proxy mounts.
        cache = self.cache(lambda request: httpx.Response(200, content=self.document))
        names = (
            "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
            "http_proxy", "https_proxy", "all_proxy",
        )
        previous = {name: os.environ.get(name) for name in names}
        for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
            os.environ[name] = "http://proxy.invalid:3128"
        try:
            client = asyncio.run(cache._http())
            self.assertFalse(client.trust_env)
            self.assertEqual(client._mounts, {})
        finally:
            for name, value in previous.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value
        asyncio.run(cache.aclose())


def _self_signed_ca(path: Path, common_name: str) -> None:
    """A CA file shaped like the one the demo edge mounts at /trust/edge-ca.pem."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))


def _common_names(context: ssl.SSLContext) -> set[str]:
    return {
        attribute[0][1]
        for issued in context.get_ca_certs()
        for attribute in issued["subject"]
        if attribute[0][0] == "commonName"
    }


@unittest.skipUnless(HAVE_CRYPTO, "httpx + PyJWT + cryptography are required")
class JwksTrustTests(unittest.TestCase):
    """`trust_env=False` must not throw the deployment's own CA away."""

    def cache(self, handler=None, **kwargs) -> JwksCache:
        transport = httpx.MockTransport(handler or (lambda request: httpx.Response(200, content=b"{}")))
        return JwksCache(JWKS_URL, transport=transport, **kwargs)

    def test_ssl_cert_file_is_the_trust_anchor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ca = Path(directory) / "edge-ca.pem"
            _self_signed_ca(ca, "MCP Demo Edge CA")
            with mock.patch.dict(os.environ, {"SSL_CERT_FILE": str(ca), "SSL_CERT_DIR": ""}):
                # No transport: this is the path the MCP server itself uses, where
                # httpx builds the transport and has to be told what to trust.
                cache = JwksCache(JWKS_URL)
                self.addCleanup(asyncio.run, cache.aclose())
                self.assertIsInstance(cache._ssl, ssl.SSLContext)
                self.assertIn("MCP Demo Edge CA", _common_names(cache._ssl))
                # The context is not merely built, it is the one the client dials with:
                # this is the assertion that fails when the demo starts returning 503.
                client = asyncio.run(cache._http())
                self.assertFalse(client.trust_env)
                self.assertIs(client._transport._pool._ssl_context, cache._ssl)

    def test_a_named_ca_that_cannot_load_stops_the_server(self) -> None:
        missing = {"SSL_CERT_FILE": "/nonexistent/edge-ca.pem", "SSL_CERT_DIR": ""}
        with mock.patch.dict(os.environ, missing), self.assertRaises(TokenError):
            self.cache()

    def test_without_env_trust_material_httpx_default_is_untouched(self) -> None:
        with mock.patch.dict(os.environ, {"SSL_CERT_FILE": "", "SSL_CERT_DIR": ""}):
            self.assertIs(self.cache()._ssl, True)


@unittest.skipUnless(HAVE_CRYPTO, "httpx + PyJWT + cryptography are required")
class JwksTlsEndToEndTests(unittest.TestCase):
    """Real TLS over a real socket, the way the Docker demo uses it.

    The deployment mounts a private CA at /trust/edge-ca.pem and points
    SSL_CERT_FILE at it. A MockTransport cannot express that, and this is exactly
    where the proxy-isolation change broke the demo: the JWKS fetch fell back to
    certifi, the edge certificate did not verify, and every token verification
    answered 503.
    """

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_jwks_is_fetched_over_https_from_a_private_ca(self) -> None:
        import http.server
        import threading

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.now(UTC)
        signer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "MCP Demo Edge CA")])
        ca = (
            x509.CertificateBuilder()
            .subject_name(signer)
            .issuer_name(signer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()), critical=False
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, content_commitment=False, key_encipherment=False,
                    data_encipherment=False, key_agreement=False, key_cert_sign=True,
                    crl_sign=True, encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .sign(private_key, hashes.SHA256())
        )
        leaf = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
            .issuer_name(signer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
                ),
                critical=False,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, content_commitment=False, key_encipherment=True,
                    data_encipherment=False, key_agreement=False, key_cert_sign=False,
                    crl_sign=False, encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(private_key.public_key()), critical=False
            )
            .sign(private_key, hashes.SHA256())
        )
        pem = private_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
        chain = Path(self.tmp.name) / "edge"
        chain.mkdir()
        (chain / "ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
        (chain / "server.pem").write_bytes(leaf.public_bytes(serialization.Encoding.PEM) + pem)

        document = _jwks_document(private_key.public_key())

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802 - http.server API
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(document)))
                self.end_headers()
                self.wfile.write(document)

            def log_message(self, *args) -> None:
                pass

        httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(certfile=str(chain / "server.pem"))
        httpd.socket = server_context.wrap_socket(httpd.socket, server_side=True)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(httpd.server_close)
        url = f"https://localhost:{httpd.server_address[1]}/realms/lab/protocol/openid-connect/certs"

        with mock.patch.dict(os.environ, {"SSL_CERT_FILE": str(chain / "ca.pem"), "SSL_CERT_DIR": ""}):
            cache = JwksCache(url, timeout=5.0)
            self.addCleanup(asyncio.run, cache.aclose())
            asyncio.run(cache.refresh())
            key = asyncio.run(cache.get_key("k1"))
        self.assertEqual(key.key_id, "k1")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
