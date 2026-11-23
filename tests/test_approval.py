"""Approval token gate tests (SEC-04 / T16).

Covers single-use `jti`, concrete-target binding (wildcard rejection), TTL
bounds, signature/claim validation, and the audit record written when the
approval gate denies before Cedar. No Node required; the Cedar-free parts
import `approval` and `pep` directly, and the server wiring tests use a fake
PEP and skip unless the MCP SDK is present.

Run from the repo root:
    python3 -m unittest discover -s tests -t .
"""

from __future__ import annotations

import asyncio
import dataclasses
import importlib.util
import json
import sys
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

LAB = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(LAB / "mcp"))

try:
    import jwt
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    HAVE_CRYPTO = True
except ImportError:  # pragma: no cover - depends on the interpreter
    HAVE_CRYPTO = False

if HAVE_CRYPTO:
    from approval import ApprovalError, ApprovalVerifier, JtiStore, SqliteJtiStore

from pep import CedarPep, Decision, UserPrincipal
from tool_registry import LOCALE_FIXTURE_ID, TOOLS_BY_NAME, USER_LOCALE

try:
    # The lab directory itself is named mcp; probe a real SDK submodule.
    HAVE_MCP = importlib.util.find_spec("mcp.server.fastmcp") is not None
except (ImportError, ValueError):  # pragma: no cover
    HAVE_MCP = False

if HAVE_MCP:
    import server
    from auth import TokenClaims

ISS = "keycloak-mcp-approval"
AUD = "keycloak-mcp"
TOOL = "set_user_locale"
ACTION = "write"
TARGET = LOCALE_FIXTURE_ID


def _real_now() -> int:
    # Tokens must be valid to PyJWT's real-clock verify_exp; the fake clock
    # drives only the verifier's own TTL checks.
    return int(time.time())


class _FakeClock:
    def __init__(self, now: int | None = None) -> None:
        self.now = _real_now() if now is None else now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: int) -> None:
        self.now += seconds


def _keypair():
    private = Ed25519PrivateKey.generate()
    return private, private.public_key()


def _token(private, *, jti="jti-1", target=TARGET, tool=TOOL, action=ACTION,
           iat=None, exp=None, iss=ISS, aud=AUD, **binding):
    iat = _real_now() if iat is None else iat
    exp = iat + 300 if exp is None else exp
    return jwt.encode(
        {"iss": iss, "aud": aud, "sub": "fixture-operator", "jti": jti, "iat": iat, "exp": exp,
         "tool": tool, "action": action, "target": target, **binding},
        private, algorithm="EdDSA",
    )


class _VerifierCase(unittest.TestCase):
    @unittest.skipUnless(HAVE_CRYPTO, "PyJWT + cryptography required (server venv)")
    def setUp(self) -> None:
        self.private, self.public = _keypair()
        self.clock = _FakeClock()
        self.verifier = ApprovalVerifier(
            self.public, issuer=ISS, audience=AUD, max_ttl=900, clock=self.clock
        )

    def verify(self, token, *, tool=TOOL, action=ACTION, target=TARGET):
        return self.verifier.verify(token, tool=tool, action=action, target=target)


class ApprovalSingleUseTests(_VerifierCase):
    def test_concrete_approval_passes_once(self) -> None:
        facts = self.verify(_token(self.private))
        self.assertTrue(facts.verified)
        self.assertEqual(facts.tool, TOOL)
        self.assertTrue(250 <= facts.expires_in <= 300)

    def test_replay_of_same_jti_is_denied(self) -> None:
        token = _token(self.private)
        self.verify(token)
        with self.assertRaises(ApprovalError) as ctx:
            self.verify(token)
        self.assertIn("already been used", str(ctx.exception))
        self.assertEqual(ctx.exception.jti, "jti-1")

    def test_replay_denied_even_when_target_matches_again(self) -> None:
        token = _token(self.private, jti="dup", target="bob")
        self.verify(token, target="bob")
        with self.assertRaises(ApprovalError):
            self.verify(token, target="bob")

    def test_distinct_jtis_are_independent(self) -> None:
        self.verify(_token(self.private, jti="a"))
        self.assertTrue(self.verify(_token(self.private, jti="b")).verified)

    def test_failed_check_does_not_consume_jti(self) -> None:
        # Wrong tool fails first; the jti must survive so a corrected request
        # with the same token is still accepted (checks precede consumption).
        token = _token(self.private, tool="other_tool", jti="keepme")
        with self.assertRaises(ApprovalError):
            self.verify(token)
        good = _token(self.private, jti="keepme")
        self.assertTrue(self.verify(good).verified)


class ApprovalWildcardTests(_VerifierCase):
    def test_wildcard_target_is_rejected(self) -> None:
        token = _token(self.private, target="*")
        with self.assertRaises(ApprovalError) as ctx:
            self.verify(token, target="alice-user-id")
        self.assertIn("wildcard approval rejected", str(ctx.exception))

    def test_concrete_target_mismatch_is_rejected(self) -> None:
        token = _token(self.private, target="alice")
        with self.assertRaises(ApprovalError) as ctx:
            self.verify(token, target="bob")
        self.assertIn("different target", str(ctx.exception))

    def test_blank_request_target_is_rejected(self) -> None:
        token = _token(self.private)
        for blank in ("", "   ", None):
            with self.assertRaises(ApprovalError) as ctx:
                self.verify(token, target=blank)
            self.assertIn("no concrete target", str(ctx.exception))

    def test_tool_action_mismatch_denied_before_replay(self) -> None:
        token = _token(self.private, action="read")
        with self.assertRaises(ApprovalError) as ctx:
            self.verify(token)
        self.assertIn("different tool or action", str(ctx.exception))


class ApprovalTtlTests(_VerifierCase):
    def test_expired_token_denied(self) -> None:
        # exp 60 s ahead (valid to PyJWT's real-clock check), fake clock past it.
        token = _token(self.private, exp=self.clock() + 60)
        self.clock.advance(61)
        with self.assertRaises(ApprovalError) as ctx:
            self.verify(token)
        self.assertIn("expired or its lifetime is too long", str(ctx.exception))

    def test_future_iat_beyond_skew_denied(self) -> None:
        token = _token(self.private, iat=self.clock() + 61, exp=self.clock() + 361)
        with self.assertRaises(ApprovalError):
            self.verify(token)

    def test_lifetime_above_max_ttl_denied(self) -> None:
        token = _token(self.private, iat=self.clock(), exp=self.clock() + 901)
        with self.assertRaises(ApprovalError) as ctx:
            self.verify(token)
        self.assertIn("lifetime is too long", str(ctx.exception))

    def test_lifetime_equal_max_ttl_allowed(self) -> None:
        token = _token(self.private, iat=self.clock(), exp=self.clock() + 900)
        self.assertTrue(self.verify(token).verified)


class ApprovalSignatureTests(_VerifierCase):
    def test_foreign_key_signature_denied(self) -> None:
        other, _ = _keypair()
        with self.assertRaises(ApprovalError) as ctx:
            self.verify(_token(other))
        self.assertIn("invalid or expired", str(ctx.exception))

    def test_wrong_audience_issuer_denied(self) -> None:
        with self.assertRaises(ApprovalError):
            self.verify(_token(self.private, aud="elsewhere"))
        with self.assertRaises(ApprovalError):
            self.verify(_token(self.private, iss="elsewhere"))

    def test_missing_required_claim_denied(self) -> None:
        now = _real_now()
        claims = {"iss": ISS, "aud": AUD, "sub": "fixture-operator", "iat": now, "exp": now + 300,
                  "tool": TOOL, "action": ACTION}
        unsigned = jwt.encode(claims, self.private, algorithm="EdDSA")
        with self.assertRaises(ApprovalError):
            self.verify(unsigned)

    def test_garbage_header_denied(self) -> None:
        with self.assertRaises(ApprovalError):
            self.verify("not-a-jwt")


class JtiStoreTests(unittest.TestCase):
    @unittest.skipUnless(HAVE_CRYPTO, "PyJWT + cryptography required (server venv)")
    def test_persistent_jti_store_serializes_competing_workers_and_reopening(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "used.sqlite3")
            clock = _FakeClock()
            stores = [SqliteJtiStore(path, clock=clock) for _ in range(2)]
            with ThreadPoolExecutor(max_workers=2) as executor:
                results = list(executor.map(lambda store: store.consume("same", clock() + 60), stores))
            self.assertEqual(sorted(results), [False, True])
            self.assertFalse(SqliteJtiStore(path, clock=clock).consume("same", clock() + 60))

    @unittest.skipUnless(HAVE_CRYPTO, "PyJWT + cryptography required (server venv)")
    def test_consume_once_then_bounded(self) -> None:
        clock = _FakeClock()
        store = JtiStore(clock=clock)
        self.assertTrue(store.consume("a", clock() + 60))
        self.assertFalse(store.consume("a", clock() + 60))
        self.assertEqual(len(store), 1)
        clock.advance(61)
        store.consume("b", clock() + 200)  # triggers prune of "a"
        self.assertEqual(len(store), 1)


class _NoNodePep(CedarPep):
    """CedarPep instance for audit tests without spawning the Node PDP."""

    def __init__(self, audit_path) -> None:  # noqa: D107 - deliberately skips super()
        self.audit_path = Path(audit_path) if audit_path else None


class AuditRejectionTests(unittest.TestCase):
    def test_rejection_record_written_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            pep = _NoNodePep(path)
            pep.audit_rejection(
                TOOLS_BY_NAME[TOOL], "Client", "mcp-admin", "lab",
                reason="approval_rejected", detail="the approval token has already been used; request a new approval",
                approval_jti="jti-1",
            )
            record = json.loads(path.read_text().strip())
            self.assertEqual(record["decision"], "deny")
            self.assertEqual(record["reasons"], ["approval_rejected"])
            self.assertEqual(record["approvalJti"], "jti-1")
            self.assertEqual(record["tool"], TOOL)
            self.assertFalse(record["failedClosed"])
            self.assertNotIn("eyJ", path.read_text())  # no JWT-shaped blob in audit

    def test_no_audit_path_is_noop(self) -> None:
        _NoNodePep(None).audit_rejection(
            TOOLS_BY_NAME[TOOL], "Client", "mcp-admin", "lab",
            reason="approval_rejected", detail="x",
        )


@unittest.skipUnless(HAVE_MCP, "the MCP SDK is required for server wiring tests")
class _RecordingAuditPep:
    def __init__(self, decision=None) -> None:
        self.authorizations = []
        self.rejections = []
        self.audit_error: OSError | None = None

    def authorize(self, *args, **kwargs):
        self.authorizations.append(kwargs)
        return Decision("deny", reasons=("test-deny",))

    async def authorize_async(self, *args, **kwargs):
        return self.authorize(*args, **kwargs)

    def audit_rejection(self, tool, principal_type, principal_id, realm, *, reason, detail,
                        approval_jti=None):
        if self.audit_error is not None:
            raise self.audit_error
        self.rejections.append({"tool": tool.name, "reason": reason, "detail": detail,
                                "principal_type": principal_type, "principal": principal_id,
                                "realm": realm, "jti": approval_jti})


@unittest.skipUnless(HAVE_MCP, "the MCP SDK is required for server wiring tests")
class ServerApprovalWiringTests(unittest.TestCase):
    @unittest.skipUnless(HAVE_CRYPTO, "PyJWT + cryptography required (server venv)")
    def setUp(self) -> None:
        self._old_runtime = server._RUNTIME
        self.private, self.public = _keypair()
        self.clock = _FakeClock()
        verifier = ApprovalVerifier(self.public, issuer=ISS, audience=AUD, max_ttl=900,
                                    clock=self.clock)
        base = server.ServerConfig.from_env(
            {
                "KC_ISSUER": "https://kc.lab.local:8443/realms/lab",
                "KC_AUDIENCE": "https://mcp.lab.local/mcp",
                "KC_URL": "https://kc.lab.local:8443",
                "KC_ALLOWED_CLIENT_IDS": "https://cimd.lab.local:8444/client-metadata.json",
                "KC_MCP_CLIENT_ENTITY_MAP": json.dumps(
                    {"https://cimd.lab.local:8444/client-metadata.json": "mcp-admin"}
                ),
            }
        )
        config = dataclasses.replace(base, approval=verifier, writes_enabled=True)
        self.pep = _RecordingAuditPep()
        server._RUNTIME = server.Runtime(config=config, pep=self.pep, admin=None)
        claims = TokenClaims(
            subject="fixture-requester",
            client_id="https://cimd.lab.local:8444/client-metadata.json",
            scopes=frozenset({USER_LOCALE.scope}), roles=frozenset({USER_LOCALE.role}),
            realm="lab", admin=False, expires_at=9_999_999_999, interactive=True,
            issuer=base.auth.issuer, audience=base.auth.audience,
        )
        server._CLAIMS.set(claims)
        self.actor = UserPrincipal(
            claims.issuer, claims.subject, claims.client_id, claims.realm, claims.scopes, claims.roles,
        ).id

    def tearDown(self) -> None:
        server._RUNTIME = self._old_runtime
        server._CLAIMS.set(None)

    def token(self, **overrides):
        binding = {"sub": self.actor, "realm": "lab", "locale": "de", **overrides}
        return _token(self.private, **binding)

    def call(self, token, *, locale="de"):
        return asyncio.run(
            server.TOOL_FUNCTIONS[TOOL](realm="lab", user_id=TARGET, locale=locale, approval=token)
        )

    def test_invalid_locale_does_not_consume_approval(self) -> None:
        token = self.token()
        self.assertIn("locale must be en, de or fr", self.call(token, locale="es")["error"])
        self.assertEqual(self.pep.authorizations, [])
        self.assertIn("Cedar denied", self.call(token)["error"])
        self.assertEqual(len(self.pep.authorizations), 1)

    def test_replay_denied_and_audited_no_cedar_call(self) -> None:
        token = self.token()
        first = self.call(token)
        # deny (test PDP), but approval gate PASSED -> authorize was reached
        self.assertIn("Cedar denied", first["error"])
        self.assertEqual(len(self.pep.authorizations), 1)
        self.assertEqual(self.pep.rejections, [])
        replay = self.call(token)
        self.assertIn("already been used", replay["error"])
        self.assertEqual(len(self.pep.authorizations), 1)  # Cedar not consulted twice
        self.assertEqual(self.pep.rejections[-1]["reason"], "approval_rejected")
        # SEC-04: the rejection must be traceable to the exact single-use approval.
        self.assertEqual(self.pep.rejections[-1]["jti"], "jti-1")

    def test_wildcard_denied_and_audited(self) -> None:
        result = self.call(self.token(target="*", jti="jti-wild"))
        self.assertIn("wildcard approval rejected", result["error"])
        self.assertEqual(len(self.pep.authorizations), 0)
        self.assertEqual(self.pep.rejections[-1]["reason"], "approval_rejected")
        self.assertEqual(self.pep.rejections[-1]["jti"], "jti-wild")

    def test_missing_token_denied_and_audited(self) -> None:
        result = self.call(None)
        self.assertIn("An operator approval is required", result["error"])
        self.assertEqual(self.pep.rejections[-1]["reason"], "approval_missing")
        # No approval was presented, so there is no jti to attribute.
        self.assertIsNone(self.pep.rejections[-1]["jti"])

    def test_audit_failure_denies_and_never_allows(self) -> None:
        self.pep.audit_error = OSError("audit log is read-only")
        result = self.call(self.token(target="*"))
        self.assertEqual(result["error"], "Authorization audit unavailable")
        self.assertEqual(self.pep.authorizations, [])

if __name__ == "__main__":  # pragma: no cover
    unittest.main()
