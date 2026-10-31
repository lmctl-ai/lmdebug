#!/usr/bin/env python3
"""Host-side regression tests for the cross-platform example supervisors."""
import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("timing", ROOT / "examples/segment/timing.py")
timing = importlib.util.module_from_spec(spec)
spec.loader.exec_module(timing)
corr_spec = importlib.util.spec_from_file_location("correlation", ROOT / "examples/correlation/correlate_https.py")
correlation = importlib.util.module_from_spec(corr_spec)
corr_spec.loader.exec_module(correlation)


class WindowsSupervisor(unittest.TestCase):
    """Call the Windows pipe implementation directly on POSIX CI."""

    def test_normal_output(self):
        result = timing._bounded_windows_run([sys.executable, "-c", "print('ok')"])
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "ok")

    def test_timeout_is_bounded(self):
        result = timing._bounded_windows_run([sys.executable, "-c", "import time; time.sleep(10)"], .05)
        self.assertEqual(result.returncode, 124)
        self.assertIn("supervisor: timeout", result.stderr)

    def test_large_output_drains_both_pipes_exactly(self):
        result = timing._bounded_windows_run([
            sys.executable, "-c",
            "import sys; sys.stdout.write('o'*100000); sys.stderr.write('e'*100000)"])
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "o" * 100000)
        self.assertEqual(result.stderr, "e" * 100000)

    def test_output_limit_is_bounded(self):
        result = timing._bounded_windows_run(
            [sys.executable, "-c", "import sys; sys.stdout.write('x' * 2000000)"], 3)
        self.assertEqual(result.returncode, 125)
        self.assertLessEqual(len(result.stdout.encode()), timing.MAX_OUTPUT)
        self.assertIn("supervisor: output_limit", result.stderr)

    def test_crlf_trace_hash_uses_raw_utf8_bytes(self):
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as directory:
            path = Path(directory) / "trace.txt"
            raw = b"line one\r\nline two\r\n"
            path.write_bytes(raw)
            self.assertEqual(correlation.read_utf8_bytes(path), raw.decode("utf-8"))
            self.assertEqual(correlation.sha256_bytes(correlation.read_utf8_bytes(path).encode()),
                             __import__("hashlib").sha256(raw).hexdigest())


if __name__ == "__main__":
    unittest.main()
