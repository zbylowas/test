"""Synthetic diagnostic scenarios using documentation addresses."""

import json
import unittest
from pathlib import Path
from uuid import UUID

from rules.mtr import VERSION, analyze, interpret
from rules.report import compare_reverse, load_rows

ROOT = Path(__file__).resolve().parents[1]
TARGET = "198.51.100.18"
SID = str(UUID(int=1))
V6 = "2001:db8::18"


def trace(
    rtts, rounds=5, phase="baseline", protocol="icmp", target=TARGET, sid=SID, terminal=None, hop2_suffix=None
):
    records = []
    for a in range(1, rounds + 1):
        for ttl, value in enumerate(rtts, 1):
            rtt = value[a - 1] if isinstance(value, list) else value
            last = ttl == len(rtts)
            addr = target if last else (f"2001:db8:1::{ttl}" if ":" in target else f"192.0.2.{ttl}")
            if ttl == 2 and hop2_suffix:
                addr = f"192.0.2.{hop2_suffix[a - 1]}"
            state = (
                (terminal or ("echo_reply" if protocol == "icmp" else "tcp_connected"))
                if last
                else "ttl_expired"
            )
            if state == "unreachable":
                addr = "192.0.2.90"
            r = {
                "schema_version": 1,
                "session_id": sid,
                "target": target,
                "protocol": protocol,
                "phase": phase,
                "family": 6 if ":" in target else 4,
                "timestamp": f"2026-11-24T12:{('baseline', 'download', 'upload', 'recovery').index(phase):02}:{a:02}Z",
                "ttl": ttl,
                "attempt": a,
                "rtt_ms": rtt,
                "status": state if rtt is not None else "timeout",
                "responder": addr if rtt is not None else None,
                "native_code": 0,
            }
            if protocol == "tcp":
                r["tcp_port"] = 443
            records.append(r)
    return records


def ids(findings):
    return [d["rule_id"] for d in findings]


class Rules020(unittest.TestCase):
    def test_single_series_fixtures(self):
        for case in json.loads((ROOT / "fixtures/mtr-v020.json").read_text(encoding="utf-8")):
            with self.subTest(name=case["name"]):
                rows = trace(
                    case["rtt"],
                    **{k: case[k] for k in ("rounds", "terminal", "protocol", "hop2_suffix") if k in case},
                )
                stats, findings = analyze(rows, case.get("networks"))
                self.assertEqual(ids(findings), case["want"])
                self.assertEqual((stats, findings), analyze(reversed(rows), case.get("networks")))
                for d in findings:
                    self.assertEqual(d["version"], VERSION)
                    self.assertTrue(
                        all(
                            d[k]
                            for k in (
                                "severity",
                                "confidence",
                                "evidence",
                                "limitations",
                                "recommended_tests",
                            )
                        )
                    )
                if case.get("protocol") == "tcp":
                    self.assertEqual(stats[3]["rcv"], 5)

    def test_repeated_loop_and_negative(self):
        rows = trace([2, 3, 4, 5, 6])
        for r in rows:
            if r["ttl"] in (3, 4):
                r["responder"] = f"192.0.2.{r['ttl'] - 2}"
        self.assertIn("route.possible_loop", ids(analyze(rows)[1]))
        self.assertNotIn("route.possible_loop", ids(analyze(rows[1:])[1]))

    def test_bufferbloat_needs_recovery_and_same_path(self):
        base = trace([2, 4])
        high = trace([2, 75], phase="upload")
        recovery = trace([2, 5], phase="recovery")
        self.assertEqual(ids(interpret(base + high + recovery)["findings"]), ["load.possible_bufferbloat"])
        self.assertFalse(interpret(base + high)["findings"])
        inverted = [r | {"timestamp": "2026-11-24T11:00:00Z"} for r in recovery]
        self.assertFalse(interpret(base + high + inverted)["findings"])
        for r in high:
            if r["ttl"] == 1:
                r["responder"] = "192.0.2.77"
        self.assertFalse(interpret(base + high + recovery)["findings"])

    def test_protocol_matching_coverage_and_legacy_port(self):
        tcp_phases = (
            trace([2, 4], protocol="tcp")
            + trace([2, 90], phase="download", protocol="tcp", terminal="tcp_refused")
            + trace([2, 4], phase="recovery", protocol="tcp")
        )
        self.assertFalse(interpret(tcp_phases)["findings"])
        icmp = trace([2, 4])
        tcp = trace([2, None], protocol="tcp")
        self.assertIn("protocol.divergence", ids(interpret(icmp + tcp)["findings"]))
        self.assertFalse(interpret(icmp + tcp[:-1])["findings"])
        for r in tcp:
            del r["tcp_port"]
        self.assertFalse(interpret(icmp + tcp)["findings"])
        tcp[0]["tcp_port"] = 443
        self.assertEqual(len(interpret(icmp + tcp)["series"]), 3)

    def test_ipv6_pair_context_and_local_error(self):
        good = trace([2, 4])
        v6 = trace([3, None], target=V6)
        self.assertFalse(interpret(good + v6)["findings"])
        self.assertIn(
            "ipv6.paired_failure", ids(interpret(good + v6, dual_stack_pair=(TARGET, V6))["findings"])
        )
        self.assertFalse(interpret(good + v6[:2], dual_stack_pair=(TARGET, V6))["findings"])
        for r in v6:
            r.update(status="unavailable", native_code=11045, rtt_ms=None, responder=None)
        stats, findings = analyze(v6)
        self.assertIsNone(stats[1]["loss_pct"])
        self.assertIn("ipv6.local_route", ids(findings))
        self.assertFalse(interpret(good + v6, dual_stack_pair=(TARGET, V6))["findings"])

    def test_asymmetry_requires_bound_endpoints_complete_paths_and_time(self):
        src = "203.0.113.9"
        forward = trace([1, 2, 3])
        back = trace([3, 2, 1], target=src, sid=str(UUID(int=2)))
        binding = {"source": src, "node": TARGET, "forward_session": SID, "reverse_session": str(UUID(int=2))}
        self.assertIn("route.possible_asymmetry", ids(compare_reverse(forward, back, binding)["findings"]))
        for r in back:
            if r["ttl"] < 3:
                r["responder"] = f"192.0.2.{3 - r['ttl']}"
        self.assertFalse(compare_reverse(forward, back, binding)["findings"])
        self.assertEqual(compare_reverse(forward, back[1:], binding)["status"], "unavailable")
        with self.assertRaises(ValueError):
            compare_reverse(forward, back, binding | {"source": TARGET})
        for r in back:
            r["timestamp"] = "2026-11-24T12:10:00Z"
        self.assertEqual(compare_reverse(forward, back, binding)["reason"], "comparison_window_exceeded")

    def test_archive_and_uniqueness(self):
        old = load_rows((ROOT / "docs/evidence/loopback.ndjson").read_bytes())
        result = interpret(old)
        self.assertEqual(result["sample_count"], len(old))
        self.assertEqual(result, interpret(reversed(old)))
        with self.assertRaises(ValueError):
            interpret(old + old[:1])
        with self.assertRaises(ValueError):
            interpret(old + [dict(old[0], session_id=SID)])
