import hashlib
import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator, FormatChecker, ValidationError
from openapi_spec_validator import validate
from referencing import Registry, Resource

BASE = Path(__file__).parent / "v1"


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def validator(name):
    registry = Registry().with_resources((p.as_uri(), Resource.from_contents(read(p)))
                                         for p in BASE.glob("*.schema.json"))
    return Draft202012Validator({"$ref": (BASE / name).as_uri()}, registry=registry,
                                format_checker=FormatChecker())


class ContractTests(unittest.TestCase):
    def test_host_pings_and_older_transfers(self):
        schema = validator("throughput.schema.json")
        doc = read(BASE.parents[1] / "fixtures/throughput.json")
        schema.validate(doc)
        sample = {"at":doc["started_at"], "status":"echo_reply", "rtt_ms":0, "native_code":0, "responder":"192.0.2.1"}
        gateway = {"target":"192.0.2.1", "planned":5, "timeout_ms":400, "reason":None, "samples":[sample]*5}
        node = dict(gateway, target=None, reason="no_reservation", samples=[])
        def report(g):
            return doc | {"host_pings":{"gateway":g, "node":node}}
        schema.validate(report(gateway))
        schema.validate(report(dict(gateway,reason="cancelled",samples=[])))
        for invalid in ([sample]*6, [dict(sample, status="timeout")], [dict(sample, rtt_ms=None)]):
            with self.assertRaises(ValidationError):
                schema.validate(report(dict(gateway,samples=invalid)))

    def test_reservation_endpoint_and_legacy_transfer(self):
        doc = read(BASE.parents[1] / "fixtures/throughput.json")
        schema = validator("throughput.schema.json")
        schema.validate(doc)
        for value in ("192.0.2.3", "2001:db8::1"):
            schema.validate(doc | {"reservation_local_ip": {"status": "ok", "value": value}})
        schema.validate(doc | {"reservation_local_ip": {"status": "unavailable", "reason": "no_reservation"}})
        for invalid in ({"status": "unavailable"}, {"status": "ok", "value": "eth0"}):
            with self.assertRaises(ValidationError):
                schema.validate(doc | {"reservation_local_ip": invalid})

    def test_inventory_privacy_and_partial_tables(self):
        doc = read(BASE.parents[1] / "fixtures/inventory-unavailable.json")
        schema = validator("inventory.schema.json")
        schema.validate(doc)
        empty = {"status": "partial", "reason": "row_limit", "total": 4, "value": []}
        schema.validate(doc | {"neighbors": empty})
        neighbor = {"index": 1, "ip": "192.0.2.2", "state": 5,
                    "mac_id": {"status": "ok", "value": "a" * 64}, "vendor": doc["wifi"]}
        schema.validate(doc | {"neighbors": {"status":"ok","value":[neighbor]}})
        with self.assertRaises(ValidationError):
            schema.validate(doc | {"neighbors": {"status":"ok","value":[neighbor | {"mac":"00:00:5E:00:53:01"}]}})
        with self.assertRaises(ValidationError):
            schema.validate(doc | {"wifi": {"status":"unavailable"}})

    def test_recorded_windows_samples(self):
        evidence = BASE.parents[1] / "docs/evidence"
        raw = (evidence / "loopback.ndjson").read_bytes()
        recorded = read(evidence / "measurements.json")["loopback"]["runs"]["parallel"]
        self.assertEqual(hashlib.sha256(raw).hexdigest(), recorded["sha256"])
        samples = [json.loads(line) for line in raw.splitlines()]
        self.assertEqual(len(samples), sum(t["samples"] for t in recorded["targets"].values()))
        schema = validator("mtr-sample.schema.json")
        for sample in samples:
            schema.validate(sample)

    def test_openapi_and_meta_schemas(self):
        path = BASE / "openapi.json"
        validate(read(path), base_uri=path.as_uri())
        self.assertEqual(read(path)["components"]["responses"]["Unauthenticated"]["description"], "Brak poświadczeń")
        for path in BASE.glob("*.schema.json"):
            Draft202012Validator.check_schema(read(path))

    def test_sample_and_chunk(self):
        row = {"schema_version": 1, "session_id": "9a8da3b5-7334-45d4-b3ac-7e7482389a16",
               "timestamp": "2026-11-24T12:00:00Z", "family": 6, "target": "::1", "protocol": "icmp",
               "phase": "baseline", "ttl": 1, "attempt": 1, "responder": "::1",
               "native_code": 0, "status": "echo_reply", "rtt_ms": 0}
        schema = validator("chunk.schema.json")
        schema.validate({"schema_version": 1, "samples": [row]})
        tcp = row | {"protocol": "tcp", "status": "tcp_connected"}
        schema.validate({"schema_version": 1, "samples": [tcp, tcp | {"tcp_port": 443}]})
        for invalid in (row | {"tcp_port": 443}, tcp | {"tcp_port": 80}):
            with self.assertRaises(ValidationError):
                schema.validate({"schema_version": 1, "samples": [invalid]})
        schema.validate({"schema_version": 1, "samples": [
            row | {"responder": None, "rtt_ms": None, "status": "unavailable", "native_code": 5}]})
        for changes in ({"ttl": 0}, {"attempt": 0}, {"target": "127.0.0.1"}, {"responder": "127.0.0.1"},
                        {"status": "timeout"}, {"status": "tcp_connected"}, {"protocol": "tcp"},
                        {"rtt_ms": -1}, {"responder": None}, {"rtt_ms": None}, {"extra": 4},
                        {"timestamp": "yesterday"}, {"session_id": "bad"}):
            with self.subTest(changes=changes), self.assertRaises(ValidationError):
                schema.validate({"schema_version": 1, "samples": [row | changes]})
        for items in ([], [row] * 257):
            with self.assertRaises(ValidationError):
                schema.validate({"schema_version": 1, "samples": items})

    def test_session_and_completion(self):
        session = {"schema_version": 1, "session_id": "9a8da3b5-7334-45d4-b3ac-7e7482389a16",
                   "started_at": "2026-11-24T12:00:00Z", "client_version": "stage0", "mode": "portable"}
        validator("session.schema.json").validate(session)
        device = {"id":session["session_id"],"method":"windows_installation_v1","reason":None}
        schema = validator("session.schema.json")
        schema.validate(session | {"device":device})
        schema.validate(session | {"device":device | {"method":"unavailable","id":None,"reason":"unavailable"}})
        for bad in (device | {"id":None}, device | {"id":"raw-key"}, device | {"method":"local_profile_v1"}):
            with self.assertRaises(ValidationError):
                schema.validate(session | {"device":bad})
        settings = {"windows_version": "10.0.26200", "targets": ["192.0.2.1", "2001:db8::1"],
                    "attempts": 5, "max_ttl": 8, "interval_ms": 150, "timeout_ms": 400,
                    "protocol": "both", "phase_control": True}
        validator("session.schema.json").validate(session | {"measurement": settings})
        for invalid in ({"targets": ["bad"]}, {"attempts": 21}, {"interval_ms": 0}):
            with self.assertRaises(ValidationError):
                validator("session.schema.json").validate(session | {"measurement": settings | invalid})
        with self.assertRaises(ValidationError):
            validator("session.schema.json").validate(session | {"source_ip": "::1"})
        schema = validator("completion.schema.json")
        end = {"schema_version": 1, "state": "partial", "chunk_count": 1,
               "ended_at": "2026-11-24T12:00:01Z"}
        schema.validate(end)
        with self.assertRaises(ValidationError):
            schema.validate(end | {"state": "open"})
