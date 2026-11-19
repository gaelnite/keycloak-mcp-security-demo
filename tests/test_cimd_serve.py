"""CIMD key-server regression tests (SEC-01, findings/cimd-exposure-verification.md).

Covers the T1 allowlist (only the three public documents are served; keys and
the minted SVID are 404) and the T2 default bind (loopback, not 0.0.0.0).
"""

from __future__ import annotations

import functools
import http.client
import http.server
import importlib.util
import sys
import tempfile
import threading
import unittest
from pathlib import Path

LAB = Path(__file__).resolve().parents[1]
SERVE = LAB / "cimd" / "serve.py"

spec = importlib.util.spec_from_file_location("cimd_serve", SERVE)
assert spec is not None and spec.loader is not None
serve = importlib.util.module_from_spec(spec)
spec.loader.exec_module(serve)

PUBLIC = ("client-metadata.json", "dynamic.json", "bundle.json")


class BindDefaultTests(unittest.TestCase):
    def test_default_bind_is_loopback(self) -> None:
        # T2: the default must never be a catch-all interface.
        self.assertEqual(serve.DEFAULT_BIND, "127.0.0.1")
        self.assertNotIn(serve.DEFAULT_BIND, ("0.0.0.0", "::", ""))

    def test_public_files_allowlist_unchanged(self) -> None:
        # T1: only the three CIMD/bundle documents are public.
        self.assertEqual(serve.Handler.PUBLIC_FILES, frozenset(PUBLIC))


class ServeMatrixTests(unittest.TestCase):
    """Start serve.Handler on a throwaway loopback port and probe the matrix."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory(prefix="cimd-serve-test-")
        root = Path(cls.tmp.name)
        for name in PUBLIC:
            (root / name).write_text(f'{{"file": "{name}"}}')
        keys = root / "keys" / "lab.local"
        keys.mkdir(parents=True)
        (keys / "ec-p256.pem").write_text("FAKE PRIVATE KEY -- must never be served")
        (root / "svid.jwt").write_text("FAKE SVID -- must never be served")

        cls.root = root
        cls.server = http.server.ThreadingHTTPServer(
            ("127.0.0.1", 0), functools.partial(serve.Handler, directory=str(root))
        )
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)
        cls.tmp.cleanup()

    def _get(self, path: str) -> tuple[int, bytes]:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            conn.request("GET", path)
            resp = conn.getresponse()
            return resp.status, resp.read()
        finally:
            conn.close()

    def test_public_documents_are_served(self) -> None:
        for name in PUBLIC:
            status, body = self._get(f"/{name}")
            self.assertEqual(status, 200, name)
            self.assertIn(name.encode(), body)
        # Query strings do not change the allowlist verdict.
        self.assertEqual(self._get("/bundle.json?x=1")[0], 200)

    def test_keys_svid_and_root_are_denied(self) -> None:
        denied = [
            "/",
            "/keys/lab.local/",
            "/keys/lab.local/ec-p256.pem",
            "/svid.jwt",
            "/../svid.jwt",
            "/tls/cert.pem",
        ]
        for path in denied:
            status, body = self._get(path)
            self.assertEqual(status, 404, f"{path} must be 404, got {status}")
            self.assertNotIn(b"FAKE", body, f"secret material leaked via {path}")

    def test_head_matches_get(self) -> None:
        for path in ("/bundle.json", "/svid.jwt"):
            conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
            try:
                conn.request("HEAD", path)
                self.assertEqual(conn.getresponse().status,
                                 200 if path == "/bundle.json" else 404)
            finally:
                conn.close()


if __name__ == "__main__":
    unittest.main()
