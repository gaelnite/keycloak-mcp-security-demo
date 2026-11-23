"""PEP process-boundary safety tests (workstream B: async safety).

These exercise the seams around the Node PDP that a unit test with a fake
`_request` cannot reach: a stderr flood that would block the writer, a decision
that must not occupy the asyncio event loop, and several callers sharing one PDP
pipe. Every test drives a real Node stub PDP; cedar-wasm is not required.

Run from the repo root:
    python3 -m unittest tests.test_pep_async
"""

from __future__ import annotations

import asyncio
import shutil
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

LAB = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(LAB / "mcp"))

from pep import STDERR_TAIL_LIMIT, CedarPep  # noqa: E402
from tool_registry import TOOLS_BY_NAME  # noqa: E402

TOOL = TOOLS_BY_NAME["get_extension_inventory"]

# A stub PDP, shaped by placeholders (never %-formatting: the JS contains % signs):
#   FLOOD    bytes written to stderr synchronously, i.e. blocking until drained
#   DELAY    simulated decision time in ms
#   MARKER   appended to stderr after the flood
#   IDENTITY name the answered policy after the principal asked about, so a caller
#            can prove it received *its own* decision
#   BOGUS    path of a one-shot flag file: the first authorize answer of the whole
#            run (not of the process) carries a foreign requestId
STUB = """
import fs from "node:fs";
import readline from "node:readline";
const flood = "e".repeat(@FLOOD@);
const delay = @DELAY@;
const marker = "@MARKER@";
const identity = @IDENTITY@;
const bogusFile = "@BOGUS@";
const emit = (payload) => process.stdout.write(JSON.stringify(payload) + "\\n");
const alreadyBogus = () => {
  try { return fs.readFileSync(bogusFile, "utf8") === "1"; } catch { return false; }
};
const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
rl.on("line", (line) => {
  if (!line.trim()) return;
  const req = JSON.parse(line);
  if (req.op === "ping") {
    emit({
      ok: true, requestId: req.requestId, cedarVersion: "stub",
      bundleHash: "0".repeat(64), policyIds: [],
    });
    return;
  }
  if (flood) fs.writeSync(2, flood);
  if (marker) fs.writeSync(2, marker + "\\n");
  const bogus = bogusFile && !alreadyBogus();
  if (bogus) fs.writeFileSync(bogusFile, "1");
  const answer = () => emit({
    ok: true,
    requestId: bogus ? "00000000000000000000000000000000" : req.requestId,
    decision: "allow",
    determiningPolicies: identity ? ["stub:" + req.principal.id] : ["stub-allow"],
    errors: [],
    warnings: [],
    bundleHash: "0".repeat(64),
  });
  if (delay) setTimeout(answer, delay); else answer();
});
"""


@unittest.skipUnless(shutil.which("node"), "Node is required for the stub PDP")
class StubPepCase(unittest.IsolatedAsyncioTestCase):
    # Async-capable base: the event-loop cases below are real coroutines, and the
    # synchronous ones run unchanged on the same harness.
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self._seq = 0

    def stub_pep(
        self,
        *,
        flood: int = 0,
        delay: int = 0,
        marker: str = "",
        identity: bool = False,
        bogus: bool = False,
        timeout_ms: int = 500,
    ) -> CedarPep:
        self._seq += 1
        script = Path(self.tmp.name) / f"stub-{self._seq}.mjs"
        script.write_text(
            STUB.replace("@FLOOD@", str(flood))
            .replace("@DELAY@", str(delay))
            .replace("@MARKER@", marker)
            .replace("@IDENTITY@", "true" if identity else "false")
            .replace("@BOGUS@", str(Path(self.tmp.name) / f"bogus-{self._seq}") if bogus else "")
        )
        pep = CedarPep(pdp_script=str(script), timeout_ms=timeout_ms)
        self.addCleanup(pep.close)
        return pep

    def ask(self, pep: CedarPep, principal_id: str = "mcp-claude"):
        return pep.authorize(
            TOOL,
            principal_type="Client",
            principal_id=principal_id,
            realm="lab",
            extensions=["core"],
        )

    async def ask_async(self, pep: CedarPep, principal_id: str = "mcp-claude"):
        return await pep.authorize_async(
            TOOL,
            principal_type="Client",
            principal_id=principal_id,
            realm="lab",
            extensions=["core"],
        )

    def wait_for_stderr(self, pep: CedarPep, needle: str, timeout: float = 3.0) -> str:
        deadline = time.monotonic() + timeout
        while True:
            tail = pep._stderr_tail()
            if needle in tail or time.monotonic() > deadline:
                return tail


class StderrDrainTests(StubPepCase):
    def test_stderr_flood_does_not_wedge_a_decision(self) -> None:
        # 256 KiB is well past the ~64 KiB pipe capacity: a PDP that logs without a
        # reader blocks inside the write and never answers, which the deadline would
        # report as a timeout. The drain thread consumes it instead.
        pep = self.stub_pep(flood=256 * 1024)
        started = time.monotonic()
        decision = self.ask(pep)
        elapsed = time.monotonic() - started
        self.assertTrue(decision.allowed, msg=str(decision.errors))
        self.assertLess(elapsed, 2.0, msg=f"the stderr flood cost {elapsed:.3f}s")

    def test_stderr_tail_is_bounded_and_keeps_the_latest_bytes(self) -> None:
        marker = "MARKER-AFTER-FLOOD"
        pep = self.stub_pep(flood=64 * 1024, marker=marker)
        self.assertTrue(self.ask(pep).allowed)
        # The tail comes from the drain buffer, never from a blocking pipe read.
        tail = self.wait_for_stderr(pep, marker)
        self.assertIn(marker, tail)
        self.assertLessEqual(len(tail), STDERR_TAIL_LIMIT)
        self.assertTrue(tail.endswith(marker))


class ConcurrencyTests(StubPepCase):
    def test_concurrent_callers_receive_their_own_responses(self) -> None:
        # One PDP, one pipe, eight threads. The stub names the principal it was
        # asked about, so a crossed stream shows up as a mismatched reason rather
        # than as a lost exception. With the request/response section unserialised
        # this fails every run: a foreign requestId, or trailing bytes from a peer.
        pep = self.stub_pep(delay=40, identity=True)
        principals = [f"client-{index}" for index in range(8)]
        reasons: dict[str, tuple[str, ...]] = {}
        failures: list[BaseException] = []

        def worker(principal_id: str) -> None:
            try:
                decision = self.ask(pep, principal_id=principal_id)
            except BaseException as exc:  # pragma: no cover - the PEP must not raise
                failures.append(exc)
                return
            reasons[principal_id] = decision.reasons

        threads = [
            threading.Thread(target=worker, args=(principal,)) for principal in principals
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=20)
        self.assertEqual([t for t in threads if t.is_alive()], [])
        self.assertEqual(failures, [])
        self.assertEqual(sorted(reasons), sorted(principals))
        for principal_id, got in reasons.items():
            self.assertEqual(got, (f"stub:{principal_id}",))
        # Serialisation is not merely "no exception": a correct stream never trips
        # the violation path, so the PDP must not have been restarted at all.
        self.assertEqual(pep._restarts, [])


class EventLoopTests(StubPepCase):
    async def test_authorize_async_leaves_the_event_loop_free(self) -> None:
        pep = self.stub_pep(delay=300, identity=True)
        ticks = 0
        running = True

        async def ticker() -> None:
            nonlocal ticks
            while running:
                await asyncio.sleep(0.01)
                ticks += 1

        task = asyncio.create_task(ticker())
        started = time.monotonic()
        decision = await self.ask_async(pep)
        elapsed = time.monotonic() - started
        running = False
        await task
        self.assertTrue(decision.allowed, msg=str(decision.errors))
        self.assertGreaterEqual(
            elapsed, 0.25, msg="the stub did not actually take long enough to prove anything"
        )
        # A blocking authorize() on the loop would starve the ticker completely.
        self.assertGreaterEqual(
            ticks, 5, msg=f"the event loop only ticked {ticks} times during a {elapsed:.3f}s decision"
        )

    async def test_concurrent_awaiters_receive_their_own_responses(self) -> None:
        pep = self.stub_pep(delay=30, identity=True)
        principals = [f"client-{index}" for index in range(6)]
        decisions = await asyncio.gather(
            *(self.ask_async(pep, principal_id=principal) for principal in principals)
        )
        for principal, decision in zip(principals, decisions, strict=True):
            self.assertTrue(decision.allowed, msg=str(decision.errors))
            self.assertEqual(decision.reasons, (f"stub:{principal}",))
        self.assertEqual(pep._restarts, [])

    async def test_foreign_response_denies_fail_closed_and_the_next_call_recovers(
        self,
    ) -> None:
        # The one-shot flag file makes exactly the first authorize of the run answer
        # with someone else's requestId, across the restart that violation triggers.
        pep = self.stub_pep(identity=True, bogus=True)
        first = await self.ask_async(pep)
        self.assertFalse(first.allowed)
        self.assertTrue(first.failed_closed)
        self.assertIn("pdp_unavailable", first.reasons)
        self.assertIsNone(pep._proc, msg="the desynchronised PDP must be torn down")
        second = await self.ask_async(pep)
        self.assertTrue(second.allowed, msg=str(second.errors))
        self.assertEqual(second.reasons, ("stub:mcp-claude",))
        # Resynchronised by exactly one budgeted respawn, not by luck.
        self.assertEqual(len(pep._restarts), 1)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
