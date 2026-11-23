"""Policy enforcement point (PEP) for the Keycloak MCP server.

Stdlib only so the offline tests run without the MCP SDK. The PEP:
* maps a verified Keycloak token + tool spec to a Cedar request;
* calls the local Node PDP (cedar-wasm) over JSON lines with a hard 500 ms deadline
  and a MAX_RESPONSE_BYTES bound enforced on every chunk read;
* serialises the whole request/response round trip under one lock, correlates every
  response by requestId, and drains the PDP's stderr into a bounded tail;
* on a deadline miss or framing violation denies that request, kills the PDP and
  lazily restarts it (with backoff) so the next request recovers; every failure
  path still denies;
* denies on any PDP/audit failure (no fallback to scope-only checks);
* appends a redacted audit record with the deciding policy IDs and bundle hash.

It never logs tool arguments, tokens, client secrets or approval tokens.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import select
import shutil
import subprocess
import threading
import time
import uuid
from collections import deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from tool_registry import ADMIN, READ, WRITE, ToolSpec

HERE = Path(__file__).resolve().parent
PDP_SCRIPT = HERE / "pdp.mjs"
DEFAULT_TIMEOUT_MS = 500
MAX_TIMEOUT_MS = 2000
# One JSON response per line; anything larger is a broken or hostile PDP stream.
MAX_RESPONSE_BYTES = 1024 * 1024
# Restarts after a violation are bounded so a wedged PDP cannot become a restart
# storm: at most MAX_RESTARTS_IN_WINDOW respawns per RESTART_WINDOW_SECONDS.
RESTART_WINDOW_SECONDS = 60.0
MAX_RESTARTS_IN_WINDOW = 5
# The PDP's stderr is drained into a fixed-size tail. An undrained pipe fills at
# ~64 KiB and then blocks the *writer*, i.e. the PDP, which would surface as a
# deadline miss on a decision; a full read() into a str could also grow without
# bound. Bytes are kept in chunks so a flood costs a few KiB, never megabytes.
STDERR_CHUNK_BYTES = 256
STDERR_TAIL_BYTES = 4096
STDERR_TAIL_LIMIT = 400
ACTION = {READ: "Read", WRITE: "Write", ADMIN: "Admin"}


class PdpError(RuntimeError):
    """PDP unavailable, malformed response, or timeout. Callers must deny."""


class PepError(RuntimeError):
    """The PEP itself is misconfigured (missing node/PDP script)."""


class _DeadlineExceeded(Exception):
    """Internal: the PDP did not complete a response line within the deadline."""


class _ResponseTooLarge(Exception):
    """Internal: the PDP produced more than MAX_RESPONSE_BYTES of response bytes."""


@dataclass(frozen=True)
class Decision:
    decision: str
    reasons: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()
    bundle_hash: str = ""
    failed_closed: bool = False

    @property
    def allowed(self) -> bool:
        return self.decision == "allow"


@dataclass(frozen=True)
class UserPrincipal:
    issuer: str
    subject: str
    client_id: str
    realm: str
    scopes: frozenset[str]
    roles: frozenset[str]

    @property
    def id(self) -> str:
        origin = json.dumps([self.issuer, self.subject]).encode("ascii")
        return "oidc:" + hashlib.sha256(origin).hexdigest()

    def to_pdp(self) -> dict[str, Any]:
        return {
            "realm": self.realm,
            "attrs": {
                "issuer": self.issuer,
                "subject": self.subject,
                "clientId": self.client_id,
                "scopes": sorted(self.scopes),
                "roles": sorted(self.roles),
                "admin": False,
            },
        }


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _approval_facts(approval: Mapping[str, Any] | None) -> tuple[bool, str]:
    if not approval:
        return False, ""
    try:
        expires = float(approval.get("expiresIn", 0))
    except (TypeError, ValueError):
        expires = 0.0
    verified = bool(approval.get("verified")) and expires > 0
    return verified, str(approval.get("tool") or "")


def build_context(
    *,
    realm: str,
    extensions: Sequence[str],
    writes_enabled: bool,
    approval_verified: bool = False,
    approval_tool: str = "",
    tool_known: bool = True,
) -> dict[str, Any]:
    return {
        "resource": {"__entity": {"type": "KeycloakMCP::Resource", "id": f"realm:{realm}"}},
        "toolKnown": bool(tool_known),
        "writesEnabled": bool(writes_enabled),
        "extensions": sorted(set(extensions) | {"core"}),
        "approvalVerified": approval_verified,
        "approvalTool": approval_tool,
    }


class CedarPep:
    """Long-lived Node PDP + fail-closed authorization + redacted audit."""

    def __init__(
        self,
        *,
        pdp_script: str | os.PathLike[str] | None = None,
        timeout_ms: int = DEFAULT_TIMEOUT_MS,
        audit_path: str | os.PathLike[str] | None = None,
        node: str | None = None,
    ) -> None:
        if not DEFAULT_TIMEOUT_MS <= int(timeout_ms) <= MAX_TIMEOUT_MS:
            raise PepError(f"timeout_ms must be {DEFAULT_TIMEOUT_MS}-{MAX_TIMEOUT_MS}")
        self.timeout = int(timeout_ms) / 1000.0
        self.audit_path = Path(audit_path) if audit_path else None
        self._script = Path(pdp_script) if pdp_script else PDP_SCRIPT
        self._node = node or shutil.which("node")
        if not self._node:
            raise PepError("node not found; the Cedar PDP requires Node 22+")
        if not self._script.is_file():
            raise PepError(f"Cedar PDP script not found: {self._script}")
        self._proc: subprocess.Popen[bytes] | None = None
        self._restarts: list[float] = []
        # stderr is written by the drain thread and read by _stderr_tail(); the
        # deque bounds the memory and the lock only guards the copy-out.
        self._stderr_chunks: deque[bytes] = deque(
            maxlen=max(1, STDERR_TAIL_BYTES // STDERR_CHUNK_BYTES)
        )
        self._stderr_lock = threading.Lock()
        # Serialises the whole PDP round trip. Reentrant: _request -> _restart ->
        # _start -> the startup ping re-enters _request on the same thread.
        self._io_lock = threading.RLock()
        self._start()

    # -- lifecycle -------------------------------------------------------
    def _start(self) -> None:
        try:
            # S603: argv-list exec (no shell) of `shutil.which("node")` against a
            # script path validated as a regular file in __init__.
            self._proc = subprocess.Popen(  # noqa: S603
                [self._node, str(self._script)],
                cwd=str(self._script.parent),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=0,
            )
        except OSError as exc:
            raise PepError(f"cannot start the Cedar PDP: {exc}") from exc
        self._start_stderr_drain(self._proc)
        # Startup loads and compiles the WASM bundle; give it more than one decision's
        # 500 ms budget. Per-decision deadlines stay at self.timeout.
        self.meta = self._request({"op": "ping"}, timeout=max(self.timeout, 2.0))

    def _start_stderr_drain(self, proc: subprocess.Popen[bytes]) -> None:
        """Drain one PDP process' stderr into the bounded tail.

        The thread owns the read end of the pipe (so `close()` never closes a fd it
        is blocked on), exits on EOF, and swallows every error: a diagnostic path
        must never raise into the PEP or wedge a decision.
        """
        stream = proc.stderr
        with self._stderr_lock:
            self._stderr_chunks.clear()
        if stream is None:
            return

        def drain() -> None:
            try:
                with stream:
                    while True:
                        chunk = stream.read(STDERR_CHUNK_BYTES)
                        if not chunk:
                            return
                        with self._stderr_lock:
                            self._stderr_chunks.append(chunk)
            except Exception:  # noqa: BLE001 - pipe closed by close(), or worse
                # A diagnostic path must never raise into the PEP, and it must not
                # leak the descriptor when the read end is already gone.
                return

        threading.Thread(target=drain, name="cedar-pdp-stderr", daemon=True).start()

    def _restart(self) -> None:
        """Respawn the PDP after a violation, bounded by a restart budget."""
        now = time.monotonic()
        self._restarts = [
            t for t in self._restarts if now - t < RESTART_WINDOW_SECONDS
        ]
        if len(self._restarts) >= MAX_RESTARTS_IN_WINDOW:
            raise PdpError(
                "the Cedar PDP is flapping; restarts are backing off for "
                f"{RESTART_WINDOW_SECONDS:.0f} s"
            )
        self._restarts.append(now)
        self.close()
        try:
            self._start()
        except PepError as exc:
            raise PdpError(f"cannot restart the Cedar PDP: {exc}") from exc

    def close(self) -> None:
        proc, self._proc = self._proc, None
        if proc is None:
            return
        try:
            if proc.stdin:
                proc.stdin.close()
        except OSError:
            pass
        try:
            proc.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        for stream in (proc.stdout,):
            # stderr is deliberately absent: the drain thread owns that descriptor
            # and closes it on EOF, so closing it here would race a blocked read.
            if stream is not None:
                with contextlib.suppress(OSError):
                    stream.close()

    def __enter__(self) -> CedarPep:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # -- authorization ---------------------------------------------------
    def authorize(
        self,
        tool: ToolSpec,
        *,
        principal_type: str,
        principal_id: str,
        realm: str,
        extensions: Sequence[str],
        writes_enabled: bool = False,
        approval: Mapping[str, Any] | None = None,
        tool_known: bool = True,
        user: UserPrincipal | None = None,
    ) -> Decision:
        approval_verified, approval_tool = _approval_facts(approval)
        context = build_context(
            realm=realm,
            extensions=extensions,
            writes_enabled=writes_enabled,
            approval_verified=approval_verified,
            approval_tool=approval_tool,
            tool_known=tool_known,
        )
        if user is not None:
            principal_type, principal_id = "User", user.id
        payload = {
            "op": "authorize",
            "principal": {"type": f"KeycloakMCP::{principal_type}", "id": principal_id},
            "action": {"type": "KeycloakMCP::Action", "id": ACTION[tool.tier]},
            "resource": {"type": "KeycloakMCP::Tool", "id": tool.name},
            "context": context,
        }
        if user is not None:
            payload["user"] = user.to_pdp()
        try:
            response = self._request(payload)
            decision = self._decision(response)
        except (PdpError, KeyError) as exc:
            decision = Decision(
                decision="deny",
                reasons=("pdp_unavailable",),
                errors=(str(exc),),
                failed_closed=True,
            )
        try:
            self._audit(tool, principal_type, principal_id, realm, decision)
        except OSError as exc:
            return Decision(
                decision="deny",
                reasons=("audit_unavailable",),
                errors=(str(exc),),
                failed_closed=True,
            )
        return decision

    @staticmethod
    def _decision(response: Mapping[str, Any]) -> Decision:
        result = response.get("decision")
        errors = response.get("errors", [])
        warnings = response.get("warnings", [])
        policies = response.get("determiningPolicies", [])
        bundle_hash = str(response.get("bundleHash") or "")
        if (
            result not in ("allow", "deny")
            or not isinstance(errors, list)
            or not isinstance(warnings, list)
            or not isinstance(policies, list)
            or not all(isinstance(policy, str) for policy in policies)
        ):
            raise PdpError("invalid decision response")
        if errors or warnings:
            reasons = ("pdp_diagnostics", *policies) if result == "deny" else ("pdp_diagnostics",)
            return Decision("deny", reasons=reasons, bundle_hash=bundle_hash, failed_closed=True)
        return Decision(result, reasons=tuple(policies), bundle_hash=bundle_hash)

    # -- protocol --------------------------------------------------------
    def _request(
        self, payload: Mapping[str, Any], *, timeout: float | None = None
    ) -> dict[str, Any]:
        # One long-lived PDP behind one pipe means a response is only meaningful
        # if it answers *this* request. pdp.mjs echoes requestId on every branch
        # (ping, validate, authorize, unknown-op), so correlation needs no change
        # on the Node side.
        request_id = uuid.uuid4().hex
        payload = {**payload, "requestId": request_id}
        # The write, the deadline-bounded read, the decode, the correlation test and
        # the kill-on-violation below form ONE critical section. Without it,
        # concurrent authorize() calls interleave on a single stream - one caller
        # reads a peer's response - and several can spend the restart budget or steal
        # the same lazy restart. The lock lives here rather than in authorize() so
        # the CedarPep.__new__ test doubles, which replace _request outright, keep
        # working without a lock attribute.
        with self._io_lock:
            if self._proc is None or self._proc.poll() is not None:
                # Violation or crash: respawn under the restart budget, then retry.
                self._restart()
            proc = self._proc
            if proc is None or proc.stdin is None or proc.stdout is None:
                raise PdpError("the Cedar PDP process is not running")
            timeout_s = self.timeout if timeout is None else timeout
            try:
                proc.stdin.write(json.dumps(payload).encode("utf-8") + b"\n")
                proc.stdin.flush()
            except OSError as exc:
                self.close()
                raise PdpError(f"cannot write to the Cedar PDP: {exc}") from exc
            try:
                line = self._read_line(proc, timeout_s)
            except _DeadlineExceeded:
                # Kills the wedged PDP; the next request restarts it (budgeted).
                self.close()
                raise PdpError(f"the Cedar PDP exceeded {timeout_s * 1000:.0f} ms") from None
            except _ResponseTooLarge:
                self.close()
                raise PdpError(
                    f"the Cedar PDP response exceeded {MAX_RESPONSE_BYTES} bytes"
                ) from None
            try:
                response = json.loads(line)
            except json.JSONDecodeError as exc:
                raise PdpError(f"the Cedar PDP returned malformed JSON: {exc}") from exc
            if not isinstance(response, dict) or not response.get("ok"):
                error = response.get("error") if isinstance(response, dict) else None
                detail = (
                    (response.get("detail") or response.get("errors"))
                    if isinstance(response, dict)
                    else response
                )
                raise PdpError(f"Cedar PDP refused ({error}): {detail}")
            if response.get("requestId") != request_id:
                # An absent or foreign id means the stream is not answering this
                # request, so the payload cannot be trusted either way: treat it as a
                # framing violation and let the budgeted restart resynchronise.
                self.close()
                raise PdpError("the Cedar PDP response did not match the request")
            return response

    def _read_line(self, proc: subprocess.Popen[bytes], timeout_s: float) -> bytes:
        """Read one newline-delimited response, deadline-bounded and size-bounded.

        The pipes are raw (bufsize=0), so select() and read() see exactly the same
        bytes; a partial line can never block past the deadline. readline() on a
        buffered text stream could hang forever on an unterminated partial line.

        The deadline and the size bound are control-dependent on the same select
        loop: every read is bounded by `remaining`, and every chunk is measured
        against MAX_RESPONSE_BYTES before the loop decides the line is complete.
        """
        stdout = proc.stdout
        assert stdout is not None  # noqa: S101 - type narrowing; _request guards the process
        buffer = bytearray()
        deadline = time.monotonic() + timeout_s
        while True:
            if buffer and b"\n" in buffer:
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _DeadlineExceeded()
            try:
                ready, _, _ = select.select([stdout], [], [], remaining)
            except (OSError, ValueError) as exc:
                raise PdpError(f"cannot wait for the Cedar PDP: {exc}") from exc
            if not ready:
                raise _DeadlineExceeded()
            chunk = stdout.read(65536)
            if not chunk:
                raise PdpError(f"the Cedar PDP exited: {self._stderr_tail()}")
            buffer.extend(chunk)
            # The size bound is checked on every chunk, before the newline test.
            # Guarding it with `b"\n" not in buffer` let a single chunk that both
            # exceeds MAX_RESPONSE_BYTES and terminates the line leave the loop and
            # return the oversized payload for parsing.
            if len(buffer) > MAX_RESPONSE_BYTES:
                raise _ResponseTooLarge()
        newline = buffer.find(b"\n")
        tail = buffer[newline + 1:]
        if tail:
            # More than one response per request is a framing violation; the stream
            # is untrustworthy, so kill the PDP (the budgeted restart fixes framing).
            if len(tail) > MAX_RESPONSE_BYTES:
                # A post-newline flood is a size violation first: bound it with the
                # same limit instead of trusting the tail length.
                raise _ResponseTooLarge()
            self.close()
            raise PdpError("the Cedar PDP streamed trailing bytes after the response")
        return bytes(buffer[:newline])

    def _stderr_tail(self) -> str:
        """The last bytes the PDP wrote to stderr, from the drain thread's buffer.

        Never blocks: reading the live pipe here would hold the request lock for as
        long as the PDP takes to exit.
        """
        with self._stderr_lock:
            chunks = list(self._stderr_chunks)
        return b"".join(chunks).decode("utf-8", "replace").strip()[-STDERR_TAIL_LIMIT:]

    # -- audit -----------------------------------------------------------
    def _audit(
        self,
        tool: ToolSpec,
        principal_type: str,
        principal_id: str,
        realm: str,
        decision: Decision,
    ) -> None:
        if self.audit_path is None:
            return
        record = {
            "ts": _now(),
            "tool": tool.name,
            "policyId": tool.policy_id,
            "tier": tool.tier,
            "extension": tool.extension,
            "principalType": principal_type,
            "principal": principal_id,
            "realm": realm,
            "decision": decision.decision,
            "reasons": list(decision.reasons),
            "failedClosed": decision.failed_closed,
            "bundleHash": decision.bundle_hash,
        }
        data = (json.dumps(record, sort_keys=True) + "\n").encode("utf-8")
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(
            str(self.audit_path), os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600
        )
        try:
            os.write(descriptor, data)
        finally:
            os.close(descriptor)

    def audit_rejection(
        self,
        tool: ToolSpec,
        principal_type: str,
        principal_id: str,
        realm: str,
        *,
        reason: str,
        detail: str,
        approval_jti: str | None = None,
    ) -> None:
        """Append a redacted deny record for a pre-Cedar gate rejection.

        Used by the approval gate (SEC-04): replay and wildcard denials must
        leave a forensic trail even though no Cedar decision was made. The
        approval token itself never appears; `approval_jti` is a public id.
        """
        if self.audit_path is None:
            return
        record = {
            "ts": _now(),
            "tool": tool.name,
            "policyId": tool.policy_id,
            "tier": tool.tier,
            "extension": tool.extension,
            "principalType": principal_type,
            "principal": principal_id,
            "realm": realm,
            "decision": "deny",
            "reasons": [reason],
            "errors": [detail],
            "failedClosed": False,
            "bundleHash": "",
        }
        if approval_jti:
            record["approvalJti"] = approval_jti
        data = (json.dumps(record, sort_keys=True) + "\n").encode("utf-8")
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(
            str(self.audit_path), os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600
        )
        try:
            os.write(descriptor, data)
        finally:
            os.close(descriptor)


def pep_from_env(env: Mapping[str, str] | None = None) -> CedarPep:
    values = dict(os.environ if env is None else env)
    try:
        timeout = int(values.get("KC_CEDAR_TIMEOUT_MS") or DEFAULT_TIMEOUT_MS)
    except ValueError as exc:
        raise PepError("KC_CEDAR_TIMEOUT_MS must be an integer") from exc
    return CedarPep(
        timeout_ms=timeout,
        audit_path=values.get("KC_MCP_AUDIT_LOG") or None,
    )
