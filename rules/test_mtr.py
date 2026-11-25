import json
from pathlib import Path
import unittest

from rules.v010 import analyze, hop_statistics, VERSION

ROOT = Path(__file__).resolve().parents[1]


def expand(case):
    for attempt, path in enumerate(case["rounds"], 1):
        for ttl, addr in enumerate(path, 1):
            if addr == "unavailable":
                status, addr = "unavailable", None
            elif addr is None:
                status = "timeout"
            elif addr == case["target"]:
                status = "echo_reply"
            else:
                status = "ttl_expired"
            rtt = 150 if case["name"] == "isolated_slow_hop" and ttl == 2 else ttl
            yield {"session_id": "00000000-0000-4000-8000-000000000001", "target": case["target"],
                   "family": 6 if ":" in case["target"] else 4, "protocol": "icmp", "phase": "baseline",
                   "attempt": attempt, "ttl": ttl, "responder": addr, "status": status,
                   "rtt_ms": rtt if addr else None}


class InterpretationTests(unittest.TestCase):
    def test_fixtures(self):
        for case in json.loads((ROOT / "fixtures/mtr-cases.json").read_text(encoding="utf-8")):
            with self.subTest(case=case["name"]):
                samples = list(expand(case))
                stats, diagnoses = analyze(samples)
                self.assertEqual(case["expected"], [d["rule_id"] for d in diagnoses])
                self.assertEqual((stats, diagnoses), analyze(reversed(samples)))
                for d in diagnoses:
                    self.assertEqual(d["version"], VERSION)
                    for key in ("severity", "confidence", "evidence", "limitations", "recommended_tests"):
                        self.assertTrue(d[key])
                if case["name"] == "api_failure":
                    self.assertIsNone(stats[1]["loss_pct"])
                    self.assertEqual(stats[1]["snt"], 0)

    def test_statistics(self):
        samples = [dict(attempt=i, status="echo_reply", responder="::1", rtt_ms=value)
                   for i, value in enumerate([0, 2, 4, 6, 8], 1)]
        s = hop_statistics(samples)
        for key, value in {"snt": 5, "rcv": 5, "last": 8, "avg": 4, "best": 0,
                           "worst": 8, "p50": 4, "p95": 8, "p99": 8,
                           "mean_abs_delta_ms": 2, "loss_pct": 0}.items():
            self.assertEqual(s[key], value)
        self.assertAlmostEqual(s["stdev"], 8 ** .5)
        samples[-1].update(status="timeout", responder=None, rtt_ms=None)
        s = hop_statistics(samples)
        self.assertIsNone(s["last"])
        self.assertEqual(s["loss_pct"], 20)

    def test_variability_uses_adjacent_attempts_on_same_responder(self):
        samples = [dict(attempt=i, status="ttl_expired", responder=a, rtt_ms=i)
                   for i, a in [(1, "::1"), (3, "::1"), (4, "::2")]]
        self.assertIsNone(hop_statistics(samples)["mean_abs_delta_ms"])

    def test_reject_mixed_or_duplicate_series(self):
        row = next(expand({"name": "unit", "target": "::1", "rounds": [["::1"]]}))
        for changed in ({}, {"session_id": "other"}, {"target": "::2"}, {"phase": "download"}):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                analyze([row, row | changed])
        with self.assertRaises(ValueError):
            analyze([row | {"protocol": "tcp"}])
