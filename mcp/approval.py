"""Operation-bound human approval for Keycloak MCP writes.

An Ed25519 compact JWT with a short TTL; claims bind the approval to
`tool`, `action` and a concrete `target` (plus `sub`, `jti`), verified offline
against a public key. The PEP receives only the derived facts
(`approvalVerified`, `approvalTool`); the token itself never reaches Cedar,
audit records or logs.

Delegated locale approvals bind the actor, realm and locale. The verifier
consumes the unique approval ID in a durable SQLite store before dispatch.
Each approval identifies one concrete target and permits one attempt.
"""

from __future__ import annotations

import os
import sqlite3
import stat
import threading
import time
from collections.abc import Mapping
from contextlib import closing
from dataclasses import dataclass
from typing import Any

import jwt


class ApprovalError(Exception):
    def __init__(self, message: str, *, jti: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.jti = jti


class JtiStore:
    """In-process single-use registry for approval `jti` values.

    Entries live until their `exp` passes (bounded by max_ttl), so memory
    growth is bounded by the number of approvals consumed within one TTL
    window.
    """

    def __init__(self, *, clock: Any = time.time) -> None:
        self._clock = clock
        self._used: dict[str, float] = {}
        self._lock = threading.Lock()

    def consume(self, jti: str, expires_at: float) -> bool:
        """Mark `jti` used. Returns False if it was already consumed."""
        now = self._clock()
        with self._lock:
            for stale in [k for k, exp in self._used.items() if exp <= now]:
                self._used.pop(stale, None)
            if jti in self._used:
                return False
            self._used[jti] = expires_at
            return True

    def __len__(self) -> int:
        with self._lock:
            return len(self._used)


class SqliteJtiStore:
    """Single-use approvals shared by workers and retained across restarts."""

    def __init__(self, path: str, *, clock: Any = time.time) -> None:
        self.path = path
        self.clock = clock
        try:
            handle = os.open(path, os.O_CREAT | os.O_NOFOLLOW | os.O_RDWR, 0o600)
            try:
                mode = os.fstat(handle).st_mode
                if not stat.S_ISREG(mode) or mode & 0o077:
                    raise ApprovalError("The approval replay database must be a private regular file")
            finally:
                os.close(handle)
            with closing(sqlite3.connect(path, timeout=0.5)) as connection, connection:
                connection.execute("CREATE TABLE IF NOT EXISTS used (jti TEXT PRIMARY KEY, expires REAL NOT NULL)")
        except (OSError, sqlite3.Error) as exc:
            raise ApprovalError("Could not initialize the approval replay database") from exc

    def consume(self, jti: str, expires_at: float) -> bool:
        try:
            connection = sqlite3.connect(self.path, timeout=0.5)
            try:
                with connection:
                    connection.execute("BEGIN IMMEDIATE")
                    connection.execute("DELETE FROM used WHERE expires <= ?", (self.clock(),))
                    inserted = connection.execute("INSERT OR IGNORE INTO used VALUES (?, ?)", (jti, expires_at))
                    return inserted.rowcount == 1
            finally:
                connection.close()
        except sqlite3.Error as exc:
            raise ApprovalError("The approval replay database is unavailable") from exc


@dataclass(frozen=True)
class ApprovalFacts:
    verified: bool
    tool: str
    expires_in: int

    def to_pep(self) -> dict[str, Any]:
        return {"verified": self.verified, "tool": self.tool, "expiresIn": self.expires_in}


class ApprovalVerifier:
    def __init__(
        self,
        public_key: Any,
        *,
        issuer: str,
        audience: str,
        max_ttl: int = 900,
        clock: Any = time.time,
        jti_store: JtiStore | SqliteJtiStore | None = None,
    ) -> None:
        self.public_key = public_key
        self.issuer = issuer
        self.audience = audience
        self.max_ttl = int(max_ttl)
        self._clock = clock
        self.jti_store = jti_store if jti_store is not None else JtiStore(clock=clock)

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> ApprovalVerifier | None:
        values = dict(os.environ if env is None else env)
        path = (values.get("KC_MCP_APPROVAL_PUBLIC_KEY_FILE") or "").strip()
        if not path:
            return None
        try:
            from cryptography.hazmat.primitives import serialization

            with open(path, "rb") as handle:
                public_key = serialization.load_pem_public_key(handle.read())
        except (OSError, ValueError) as exc:
            raise ApprovalError(f"cannot load KC_MCP_APPROVAL_PUBLIC_KEY_FILE: {exc}") from exc
        replay_path = (values.get("KC_MCP_APPROVAL_REPLAY_DB") or "").strip()
        try:
            max_ttl = int(values.get("KC_MCP_APPROVAL_MAX_TTL") or "900")
        except ValueError as exc:
            raise ApprovalError("KC_MCP_APPROVAL_MAX_TTL must be an integer") from exc
        if max_ttl <= 0:
            raise ApprovalError("KC_MCP_APPROVAL_MAX_TTL must be positive")
        return cls(
            public_key,
            issuer=(values.get("KC_MCP_APPROVAL_ISSUER") or "keycloak-mcp-approval").strip(),
            audience=(values.get("KC_MCP_APPROVAL_AUDIENCE") or "keycloak-mcp").strip(),
            max_ttl=max_ttl,
            jti_store=SqliteJtiStore(replay_path) if replay_path else None,
        )

    def verify(
        self,
        token: str,
        *,
        tool: str,
        action: str,
        target: str,
        subject: str | None = None,
        realm: str | None = None,
        locale: str | None = None,
    ) -> ApprovalFacts:
        if not isinstance(token, str) or len(token) > 4096 or token.count(".") != 2:
            raise ApprovalError(
                "the approval must be a signed token from the operator"
            )
        try:
            claims = jwt.decode(
                token,
                self.public_key,
                algorithms=["EdDSA"],
                audience=self.audience,
                issuer=self.issuer,
                options={
                    "require": ["exp", "iat", "sub", "jti", "tool", "action", "target"],
                    "verify_exp": True,
                    "verify_iat": False,
                    "verify_aud": True,
                    "verify_iss": True,
                },
            )
        except jwt.PyJWTError as exc:
            raise ApprovalError("the approval token is invalid or expired") from exc
        jti = str(claims["jti"])
        now = self._clock()
        issued, expires = claims["iat"], claims["exp"]
        if (
            not isinstance(issued, int) or not isinstance(expires, int)
            or issued > now + (0 if subject is not None else 60)
            or expires <= now or not 0 < expires - issued <= self.max_ttl
        ):
            raise ApprovalError(
                "the approval token is expired or its lifetime is too long", jti=jti
            )
        if not isinstance(target, str) or not target.strip():
            raise ApprovalError(
                "the write has no concrete target; approval requires the exact user or realm",
                jti=jti,
            )
        if claims.get("tool") != tool or claims.get("action") != action:
            raise ApprovalError(
                "the approval token is bound to a different tool or action; request a new approval",
                jti=jti,
            )
        claim_target = claims.get("target")
        if claim_target == "*":
            raise ApprovalError(
                'wildcard approval rejected; target="*" is not allowed for destructive '
                "tools — request an approval bound to the exact target",
                jti=jti,
            )
        if claim_target != target:
            raise ApprovalError(
                "the approval token is bound to a different target; request a new approval",
                jti=jti,
            )
        if subject is not None and (
            claims["sub"] != subject or claims.get("realm") != realm or claims.get("locale") != locale
            or claims.get("aud") != self.audience
        ):
            raise ApprovalError("The approval is bound to a different user, realm or locale", jti=jti)
        if not self.jti_store.consume(jti, expires):
            raise ApprovalError(
                "the approval token has already been used; request a new approval", jti=jti
            )
        return ApprovalFacts(verified=True, tool=str(claims["tool"]), expires_in=int(expires - now))
