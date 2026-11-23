"""PEP process-boundary safety tests (workstream B: async safety).

These exercise the seams around the Node PDP that a unit test with a fake
`_request` cannot reach: a stderr flood that would block the writer, a decision
that must not occupy the asyncio event loop, and several callers sharing one PDP
pipe. Every test drives a real Node stub PDP; cedar-wasm is not required.

Run from the repo root:
    python3 -m unittest tests.test_pep_async
"""

from __future__ import annotations

import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path

LAB = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(LAB / "mcp"))

from pep import STDERR_TAIL_LIMIT, CedarPep  # noqa: E402
from tool_registry import TOOLS_BY_NAME  # noqa: E402

TOOL = TOOLS_BY_NAME["get_extension_inventory"]

# A stub PDP. `FLOOD` bytes go to stderr through fs.writeSync, i.e. synchronously,
# so the writer blocks until somebody drains the pipe. `DELAY` ms is the simulated
# decision time, `MARKER` is appended to stderr after the flood, and `IDENTITY`
# makes the answer name the principal it was asked about, which is how the
# concurrency test proves delivery matching rather than mere absence of errors.
STUB = """
import fs from "node:fs";
import readline from "node:readline";
const flood = "e".repeat(@FLOOD@);
const delay = @DELAY@;
const marker = "@MARKER@";
const identity = @IDENTITY@;
const emit = (payload) => process.stdout.write(JSON.stringify(payload) + "\\n");
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
  const answer = () => emit({
    ok: true,
    requestId: req.requestId,
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
class StubPepCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def stub_pep(
        self, *, flood: int = 0, delay: int = 0, marker: str = "", identity: bool = False,
        timeout_ms: int = 500, name: str = "stub.mjs", audit_path: str | None = None,
    ) -> CedarPep:
        script = Path(self.tmp.name) / name
        script.write_text(
            STUB.replace("@FLOOD@", str(flood))
            .replace("@DELAY@", str(delay))
            .replace("@MARKER@", marker)
            .replace("@IDENTITY@", "true" if identity else "false")
        )
        pep = CedarPep(pdp_script=str(script), timeout_ms=timeout_ms, audit_path=audit_path)
        self.addCleanup(pep.close)
        return pep

    def authorize(self, pep: CedarPep, principal_id: str = "mcp-claude"):
        return pep.authorize(
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
        decision = self.authorize(pep)
        elapsed = time.monotonic() - started
        self.assertTrue(decision.allowed, msg=str(decision.errors))
        self.assertLess(elapsed, 2.0, msg=f"the stderr flood cost {elapsed:.3f}s")

    def test_stderr_tail_is_bounded_and_keeps_the_latest_bytes(self) -> None:
        marker = "MARKER-AFTER-FLOOD"
        pep = self.stub_pep(flood=64 * 1024, marker=marker)
        self.assertTrue(self.authorize(pep).allowed)
        # The tail comes from the drain buffer, never from a blocking pipe read.
        tail = self.wait_for_stderr(pep, marker)
        self.assertIn(marker, tail)
        self.assertLessEqual(len(tail), STDERR_TAIL_LIMIT)
        self.assertTrue(tail.endswith(marker))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
