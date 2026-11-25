"""Build-independent acceptance checks against the actual native EXE."""
import ctypes
import json
import os
from pathlib import Path
import signal
import sqlite3
from contextlib import closing
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from contracts.test_contracts import validator


class WindowsTests(unittest.TestCase):
    def test_controlled_load_windows(self):
        from phase_loopback import capture
        with tempfile.TemporaryDirectory() as temp:
            evidence = Path(temp)
            result = capture(EXE, dict(os.environ, VIPNET_QUEUE_DIR=str(evidence / "queue")), evidence)
            self.assertTrue(all(n > 0 for n in result["load_bytes"].values()))
            validate = validator("mtr-sample.schema.json").validate
            for line in (evidence / "loopback.ndjson").read_bytes().splitlines():
                validate(json.loads(line))

    def test_closed_controller_seals_partial(self):
        with tempfile.TemporaryDirectory() as temp:
            r = subprocess.run([EXE,"1","2","400","127.0.0.1","--phase-control"],input=b"B",
                               capture_output=True,timeout=5,env=dict(os.environ,VIPNET_QUEUE_DIR=temp))
            self.assertEqual(r.returncode, 1)
            self.assertIn(b"phase_signal_missing_or_invalid",r.stderr)
            row = json.loads(r.stdout)
            with closing(sqlite3.connect(Path(temp)/"queue.sqlite3")) as db:
                ending = db.execute("SELECT ending FROM session WHERE id=?",(row["session_id"],)).fetchone()
                self.assertEqual(json.loads(ending[0])["state"],"partial")

    def test_live_recording_survives_parallel_recovery(self):
        with subprocess.Popen([EXE, "20", "1", "400", "::1"], stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE) as active:
            row = json.loads(active.stdout.readline())
            try:
                # Without credentials sync performs orphan recovery, then stops before transport.
                subprocess.run([EXE, "--sync"], capture_output=True, timeout=5)
                with closing(sqlite3.connect(Path(os.environ["VIPNET_QUEUE_DIR"]) / "queue.sqlite3")) as db:
                    value = db.execute("SELECT ending FROM session WHERE id=?", (row["session_id"],)).fetchone()
                    self.assertEqual(value, (None,))
                second = subprocess.run([EXE,"1","1","400","127.0.0.1"],capture_output=True,check=True,timeout=5)
                self.assertNotEqual(json.loads(second.stdout)["session_id"],row["session_id"])
            finally:
                active.communicate(timeout=8)
        self.assertEqual(active.returncode, 0)

    def test_live_loopback(self):
        r = subprocess.run([EXE, "3", "2", "400", "127.0.0.1", "::1"],
                           capture_output=True, check=True, timeout=10)
        rows = [json.loads(line) for line in r.stdout.splitlines()]
        validate_sample = validator("mtr-sample.schema.json").validate
        for row in rows:
            validate_sample(row)
            self.assertEqual(row["status"], "echo_reply")
            self.assertEqual(row["responder"], row["target"])
        self.assertEqual({r["session_id"] for r in rows}, {rows[0]["session_id"]})
        self.assertEqual(sorted((r["family"], r["attempt"], r["ttl"]) for r in rows),
                         [(f, a, 1) for f in (4, 6) for a in (1, 2, 3)])
        resources = json.loads(r.stderr)
        self.assertGreater(resources["peak_working_set_bytes"], 0)
        self.assertFalse(resources["cancelled"])

    def test_reject_before_probing(self):
        for args in (["1", "33", "500", "::1"], ["0", "2", "500", "::1"],
                     ["1", "1", "10", "::1"], ["1", "2", "500", "example.invalid"],
                     ["1", "1", "500", "ff02::1"], ["1", "1", "500", "224.0.0.1"],
                     ["1", "1", "500", "::1", "0:0:0:0:0:0:0:1"]):
            r = subprocess.run([EXE, *args], capture_output=True, timeout=5)
            self.assertNotEqual(r.returncode, 0)
            self.assertFalse(r.stdout)

    def test_cancel_keeps_partial_records(self):
        kernel = ctypes.windll.kernel32
        if not kernel.GetConsoleCP() and not kernel.AllocConsole():
            self.fail("could not allocate test console")
        with subprocess.Popen([EXE, "20", "2", "400", "::1"], stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, creationflags=subprocess.CREATE_NEW_PROCESS_GROUP) as child:
            first = child.stdout.readline()
            child.send_signal(signal.CTRL_BREAK_EVENT)
            tail, meta = child.communicate(timeout=5)
        rows = [json.loads(line) for line in (first + tail).splitlines()]
        self.assertEqual(child.returncode, 130)
        self.assertTrue(json.loads(meta)["cancelled"])
        self.assertGreaterEqual(len(rows), 1)
        self.assertLess(len(rows), 20)
        for r in rows:
            validator("mtr-sample.schema.json").validate(r)
        with closing(sqlite3.connect(Path(os.environ["VIPNET_QUEUE_DIR"]) / "queue.sqlite3")) as db:
            body = db.execute("SELECT ending FROM session WHERE id=?", (rows[0]["session_id"],)).fetchone()[0]
            self.assertEqual(json.loads(body)["state"], "cancelled")


if __name__ == "__main__":
    EXE = str(Path(sys.argv.pop(1)).resolve(strict=True))
    os.environ.pop("VIPNET_API_ORIGIN", None)
    os.environ.pop("VIPNET_TOKEN", None)
    with tempfile.TemporaryDirectory(prefix="vipnet-accept-") as scratch:
        os.environ["VIPNET_QUEUE_DIR"] = scratch
        unittest.main()
