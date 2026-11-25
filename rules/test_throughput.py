import copy
import json
import unittest
from pathlib import Path

from contracts.test_contracts import validator
from rules.throughput import interpret

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures/throughput.json"


class ThroughputTests(unittest.TestCase):
    def setUp(self):
        self.doc = json.loads(FIXTURE.read_text())

    def test_phase_rates_and_medians(self):
        validator("throughput.schema.json").validate(self.doc)
        result = interpret(self.doc)
        self.assertEqual(result["directions"]["download"]["median_increase_ms"], 25)
        self.assertEqual(result["directions"]["download"]["status"], "elevated_under_load")
        self.assertEqual(result["directions"]["upload"]["status"], "no_elevation_at_measured_rate")
        self.assertAlmostEqual(result["directions"]["upload"]["goodput_mbps"], 0.524288)
        self.assertEqual(result["recovery_minus_baseline_ms"], 1)
        self.assertEqual(result["directions"]["download"]["bufferbloat"], "possible_bufferbloat")
        self.doc["phases"]["recovery"] = []
        self.assertEqual(interpret(self.doc)["directions"]["download"]["bufferbloat"], "inconclusive")

    def test_missing_or_failed_samples(self):
        rows = self.doc["phases"]["download"]
        self.doc["phases"]["download"] = rows + [{"at": rows[0]["at"], "ms": None, "error": "timeout"}] * 2
        self.assertEqual(interpret(self.doc)["directions"]["download"]["reason"], "insufficient_latency_samples")
        self.doc["transfers"]["upload"]["node_bytes"] -= 1
        self.assertIsNone(interpret(self.doc)["directions"]["upload"]["goodput_mbps"])

    def test_windowed_counts_allow_variable_size(self):
        self.doc["profile"] = {"mode":"windowed","bytes":512<<20,"window_ms":5000,"streams":4,
                               "rate_bps":1000000000,"deadline_s":90}
        validator("throughput.schema.json").validate(self.doc)
        for value, valid in ((65536,True),(0,False),((512<<20)+1,False)):
            self.doc["transfers"]["upload"].update(client_bytes=value,node_bytes=value)
            rate=interpret(self.doc)["directions"]["upload"]["goodput_mbps"]
            self.assertEqual(rate is not None, valid)

    def test_old_session_reader(self):
        reader = validator("session.schema.json")
        session = {"schema_version": 1, "session_id": self.doc["session_id"], "started_at": self.doc["started_at"],
                   "client_version": "0.3.0", "mode": "portable"}
        reader.validate(session)
        reader.validate(dict(session, throughput=copy.deepcopy(self.doc)))
