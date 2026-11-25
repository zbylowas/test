"""Integration suite; the acceptance harness provides an isolated database and credentials."""

import gzip
import json
import os
import ssl
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from uuid import uuid4

import httpx
import psycopg

from rules.mtr import VERSION
from server import worker

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = json.loads((ROOT / "docs/evidence/loopback.ndjson").read_bytes().splitlines()[0])


class SessionTests(unittest.TestCase):
    def test_portal_roles_and_legacy_session(self):
        self.open()
        for token, role, visible in (("TEST_CLIENT","client",True),("TEST_READER","operator",True),
                                     ("TEST_OTHER","client",False)):
            headers = {"Authorization": "Bearer " + os.environ[token]}
            self.assertEqual(self.client.get("portal/me", headers=headers).json(), {"role": role})
            response = self.client.get("portal/sessions?state=open&limit=50", headers=headers)
            self.assertEqual(response.status_code, 200)
            ids = {row["session_id"] for row in response.json()["items"]}
            self.assertEqual(self.sid in ids, visible)
            self.assertEqual(self.client.get(self.path + "/throughput", headers=headers).status_code, 404)
        reader = {"Authorization": "Bearer " + os.environ["TEST_READER"]}
        self.assertEqual(self.client.post("portal/runs/" + self.sid, headers=reader).status_code, 403)
        self.assertEqual(self.client.get("portal/sessions?limit=0").status_code, 422)

    def test_ip_change_and_offline_delivery(self):
        device = str(uuid4())
        addresses = ("192.0.2.21", "2001:db8::41")
        delivery = "198.51.100.50"
        ids = []
        edge = os.environ["TEST_EDGE"]
        for ip in addresses:
            sid = str(uuid4())
            headers = {"x-forwarded-for": ip, "x-forwarded-proto": "https"}
            offer = self.client.post(edge + "/api/v1/portal/runs/" + sid, headers=headers)
            self.assertEqual(offer.status_code, 201)
            self.assertEqual(offer.json()["observed_ip"], ip)
            path = edge + "/measure/v1/runs/" + sid + "/finish"
            self.assertEqual(self.client.post(path, headers={"Authorization":"Bearer " + offer.json()["ticket"]}).status_code, 204)
            path = "sessions/" + sid
            opening = self.opening | {"session_id": sid, "device": {"id":device,"method":"windows_installation_v1","reason":None}}
            headers["x-forwarded-for"] = delivery
            self.assertEqual(self.client.put(edge + "/api/v1/" + path, json=opening, headers=headers).status_code, 201)
            self.assertEqual(self.client.put(path, json=opening).status_code, 200)
            self.assertEqual(self.client.put(path + "/completion", json=self.end | {"chunk_count":0}).status_code, 202)
            ids.append(sid)
        for role in ("TEST_CLIENT", "TEST_READER", "TEST_OTHER", "TEST_SIBLING"):
            auth = {"Authorization": "Bearer " + os.environ[role]}
            rows = self.client.get("portal/sessions", params={"device_id":device},headers=auth).json()["items"]
            if role in {"TEST_OTHER","TEST_SIBLING"}:
                self.assertEqual(rows, [])
                self.assertEqual(self.client.get("sessions/" + ids[0] + "/mtr",headers=auth).status_code, 404)
                continue
            self.assertEqual({row["session_id"] for row in rows}, set(ids))
            self.assertEqual({row["ip"] for row in rows}, set(addresses))
            self.assertTrue(all(row["sync_ip"] == delivery and row["ip_source"] == "reservation" for row in rows))
            for ip,sid in zip(addresses,ids):
                rows = self.client.get("portal/sessions", params={"ip":ip,"device_id":device},headers=auth).json()["items"]
                self.assertEqual([row["session_id"] for row in rows],[sid])

    def test_transfer_series_round_trip(self):
        doc = json.loads((ROOT / "fixtures/throughput.json").read_text())
        doc["session_id"] = self.sid
        trace = {"session_id": self.sid, "download": [[0, 0], [100, 1200]], "upload": []}
        doc["desktop_trace"] = trace
        self.opening["throughput"] = doc
        for invalid in ([[0, 1]], [[0, 0], [0, 100]], [[0, 0], [10, 20], [20, 10]], [[0, 0], [20, 536870912]]):
            trace["download"] = invalid
            self.assertEqual(self.client.put(self.path, json=self.opening).status_code, 422)
        trace["download"] = [[0, 0], [150, 1400]]
        trace["session_id"] = str(uuid4())
        self.assertEqual(self.client.put(self.path, json=self.opening).status_code, 422)
        trace["session_id"] = self.sid
        self.open()
        self.assertEqual(self.client.get(self.path + "/throughput").json()["throughput"]["desktop_trace"], trace)

    def test_throughput_history_and_scope(self):
        doc = json.loads((ROOT / "fixtures/throughput.json").read_text())
        self.opening.update(throughput=doc, client_version="0.4.0")
        self.assertEqual(self.client.put(self.path, json=self.opening).status_code, 422)
        doc["session_id"] = self.sid
        doc["transfers"]["upload"]["node_bytes"] -= 1
        self.assertEqual(self.client.put(self.path, json=self.opening).status_code, 422)
        doc["transfers"]["upload"]["node_bytes"] += 1
        self.open()
        self.assertEqual(self.client.put(self.path, json=self.opening).status_code, 200)
        self.assertEqual(self.client.put(self.path + "/completion", json=self.end | {"chunk_count": 0}).status_code, 202)
        response = self.client.get(self.path + "/throughput")
        self.assertEqual(response.json()["throughput"], doc)
        self.assertEqual(response.json()["interpretation"]["directions"]["download"]["status"], "elevated_under_load")
        other = {"Authorization": "Bearer " + os.environ["TEST_OTHER"]}
        self.assertEqual(self.client.get(self.path + "/throughput", headers=other).status_code, 404)

    def test_expired_inventory_keeps_session_history(self):
        import subprocess
        import sys

        self.opening["inventory"] = json.loads(
            (ROOT / "fixtures/inventory-unavailable.json").read_text(encoding="utf-8")
        )
        self.open()
        self.assertEqual(self.finish(chunk_count=0).status_code, 202)
        with psycopg.connect(os.environ["TEST_OWNER_DSN"]) as db:
            db.execute(
                "UPDATE core.session SET received_at=now()-interval '91 days' WHERE id=%s", (self.sid,)
            )
        subprocess.run(
            [sys.executable, "-m", "server.maintenance"],
            env=dict(os.environ, VIPNET_DATABASE_URL=os.environ["TEST_OWNER_URL"], VIPNET_RAW_DAYS="90"),
            capture_output=True,
            check=True,
            timeout=20,
        )
        self.assertEqual(self.client.get(self.path + "/inventory").status_code, 404)
        self.assertEqual(self.client.get(self.path).json()["state"], "completed")

    def test_inventory_only_history_scope_and_replay(self):
        doc = json.loads((ROOT / "fixtures/inventory-unavailable.json").read_text(encoding="utf-8"))
        self.opening.update(inventory=doc, client_version="0.3.0")
        self.open()
        self.assertEqual(self.client.put(self.path, json=self.opening).status_code, 200)
        self.assertEqual(self.finish(chunk_count=0).status_code, 202)
        self.assertEqual(self.client.get(self.path + "/inventory").json(), doc)
        for name, status_code in (("TEST_READER", 200), ("TEST_OTHER", 404)):
            headers = {"authorization": "Bearer " + os.environ[name]}
            self.assertEqual(
                self.client.get(self.path + "/inventory", headers=headers).status_code, status_code
            )
        with psycopg.connect(os.environ["TEST_OWNER_DSN"]) as db:
            self.assertEqual(
                db.execute(
                    "SELECT count(*) FROM diagnostics.job WHERE session_id=%s", (self.sid,)
                ).fetchone(),
                (0,),
            )

    def setUp(self):
        self.client = httpx.Client(
            base_url=os.environ["TEST_API"] + "/api/v1/",
            verify=ssl.create_default_context(cafile=os.environ["TEST_CERT"]),
            trust_env=False,
            headers={"Authorization": "Bearer " + os.environ["TEST_CLIENT"]},
        )
        self.addCleanup(self.client.close)
        self.sid = str(uuid4())
        self.path = "sessions/" + self.sid
        self.opening = dict(
            schema_version=1,
            session_id=self.sid,
            client_version="0.1.0",
            started_at="2026-11-24T00:00:00Z",
            mode="portable",
        )
        self.end = dict(schema_version=1, state="completed", chunk_count=1, ended_at="2026-11-24T00:01:00Z")

    def open(self):
        self.assertEqual(self.client.put(self.path, json=self.opening).status_code, 201)

    def sample(self, n=1):
        return dict(
            SAMPLE, session_id=self.sid, family=4, target="192.0.2.4", responder="192.0.2.4", attempt=n
        )

    def chunk(self, n, samples):
        return self.client.put(self.path + f"/chunks/{n}", json={"schema_version": 1, "samples": samples})

    def finish(self, **overrides):
        return self.client.put(self.path + "/completion", json=self.end | overrides)

    def test_concurrent_replay_and_fenced_worker(self):
        with ThreadPoolExecutor(4) as pool:
            codes = list(
                pool.map(lambda _: self.client.put(self.path, json=self.opening).status_code, range(4))
            )
        self.assertEqual(sorted(codes), [200, 200, 200, 201])
        with ThreadPoolExecutor(4) as pool:
            self.assertEqual(
                list(pool.map(lambda _: self.chunk(0, [self.sample()]).status_code, range(4))), [204] * 4
            )
        self.assertEqual(self.finish().status_code, 202)
        self.assertEqual(self.client.get(self.path + "/mtr?limit=1").json()["items"], [self.sample()])
        self.assertEqual(self.client.get(self.path + "/mtr?offset=1").json()["items"], [])
        self.assertEqual(self.finish().status_code, 200)
        self.assertEqual(self.chunk(0, [self.sample()]).status_code, 204)
        self.assertEqual(self.chunk(0, [self.sample(2)]).status_code, 409)
        self.assertEqual(self.finish(state="partial").status_code, 409)
        self.assertEqual(self.chunk(1, [self.sample(2)]).status_code, 409)
        with psycopg.connect(os.environ["TEST_OWNER_DSN"]) as db:
            # Reserve this job for the fencing check, independent of earlier test order.
            db.execute(
                "UPDATE diagnostics.job SET available_at=now()-interval '1 day' WHERE session_id=%s",
                (self.sid,),
            )
        first = worker.claim()
        self.assertEqual(str(first[0]), self.sid)
        with psycopg.connect(os.environ["TEST_OWNER_DSN"]) as db:
            db.execute(
                "UPDATE diagnostics.job SET lease_until=now()-interval '1 second' WHERE session_id=%s",
                (self.sid,),
            )
        second = worker.claim()
        self.assertEqual(second[1], first[1] + 1)
        self.assertFalse(worker.process(first))
        self.assertTrue(worker.process(second))
        with psycopg.connect(os.environ["TEST_OWNER_DSN"]) as db:
            result = db.execute(
                "SELECT result FROM diagnostics.analysis WHERE session_id=%s AND rules_version=%s",
                (self.sid, VERSION),
            ).fetchone()[0]
        self.assertEqual(result["sample_count"], 1)
        self.assertEqual(result["series"][0]["findings"][0]["rule_id"], "sample.insufficient")

    def test_historical_reanalysis_and_scoped_read(self):
        from rules.v010 import analyze as old_analyze

        self.open()
        row = self.sample()
        self.assertEqual(self.chunk(0, [row]).status_code, 204)
        self.assertEqual(self.finish().status_code, 202)
        path = self.path + "/analysis"
        self.assertEqual(self.client.get(path).status_code, 404)
        stats, findings = old_analyze([row])
        historical = {
            "sample_count": 1,
            "series": [
                {
                    "target": row["target"],
                    "protocol": "icmp",
                    "phase": "baseline",
                    "stats": stats,
                    "findings": findings,
                }
            ],
        }
        with psycopg.connect(os.environ["TEST_OWNER_DSN"]) as db:
            import hashlib

            checksum = hashlib.sha256(
                db.execute("SELECT digest FROM core.chunk WHERE session_id=%s", (self.sid,)).fetchone()[0]
            ).digest()
            db.execute(
                "INSERT INTO diagnostics.analysis(session_id,rules_version,input_digest,result) "
                "VALUES (%s,'0.1.0',%s,%s::jsonb)",
                (self.sid, checksum, json.dumps(historical)),
            )
            db.execute("UPDATE diagnostics.job SET state='done' WHERE session_id=%s", (self.sid,))
        with ThreadPoolExecutor(2) as pool:
            self.assertEqual(sorted(pool.map(worker.reanalyze, [self.sid] * 2)), [False, True])
        old = self.client.get(path, params={"rules_version": "0.1.0"}).json()
        self.assertEqual(old["result"], json.loads(json.dumps(historical)))
        current = self.client.get(
            path, headers={"authorization": "Bearer " + os.environ["TEST_READER"]}
        ).json()
        self.assertEqual((current["rules_version"], current["input_sha256"]), (VERSION, checksum.hex()))
        self.assertEqual(
            self.client.get(
                path, headers={"authorization": "Bearer " + os.environ["TEST_OTHER"]}
            ).status_code,
            404,
        )

    def test_manifest_atomicity_and_order(self):
        self.open()
        self.assertEqual(self.chunk(1, [self.sample(2)]).status_code, 204)
        self.assertEqual(self.finish().status_code, 409)
        self.assertEqual(self.chunk(0, [self.sample(1), self.sample(2)]).status_code, 409)
        self.assertEqual(self.chunk(0, [self.sample(1)]).status_code, 204)
        self.assertEqual(self.finish(chunk_count=2, state="cancelled").status_code, 202)
        self.assertEqual(self.client.get(self.path).json()["state"], "cancelled")

    def test_stage_zero_record_reader(self):
        rows = [
            json.loads(line) for line in (ROOT / "docs/evidence/loopback.ndjson").read_bytes().splitlines()
        ]
        self.sid = rows[0]["session_id"]
        self.path = "sessions/" + self.sid
        self.opening["session_id"] = self.sid
        self.open()
        self.assertEqual(self.chunk(0, rows).status_code, 204)
        self.assertEqual(self.finish().status_code, 202)
        with psycopg.connect(os.environ["TEST_OWNER_DSN"]) as db:
            saved = db.execute(
                "SELECT payload FROM mtr.sample WHERE session_id=%s ORDER BY row_no", (self.sid,)
            ).fetchall()
        self.assertEqual(rows, [r[0] for r in saved])

    def test_rate_limit(self):
        import hashlib

        token = os.environ["TEST_OTHER"]
        digest = hashlib.sha256(token.encode()).digest()
        with psycopg.connect(os.environ["TEST_OWNER_DSN"]) as db:
            db.execute(
                "UPDATE security.principal SET rate_minute=date_trunc('minute',now()),rate_count=300 "
                "WHERE token_hash=%s",
                (digest,),
            )
        try:
            res = self.client.get("sessions", headers={"authorization": "Bearer " + token})
            self.assertEqual(res.status_code, 429)
            self.assertGreater(int(res.headers["retry-after"]), 0)
        finally:
            with psycopg.connect(os.environ["TEST_OWNER_DSN"]) as db:
                db.execute("UPDATE security.principal SET rate_count=0 WHERE token_hash=%s", (digest,))

    def test_token_rotation_and_revocation(self):
        import subprocess
        import sys

        owner_env = dict(os.environ, VIPNET_DATABASE_URL=os.environ["TEST_OWNER_URL"])
        base = [sys.executable, "-m", "server"]
        issued = subprocess.run(
            [*base, "issue-token", str(uuid4()), "client"],
            env=owner_env,
            check=True,
            capture_output=True,
            text=True,
        )
        principal = issued.stderr.strip().removeprefix("principal=")
        original = {"authorization": "Bearer " + issued.stdout.strip()}
        self.assertEqual(self.client.put(self.path, json=self.opening, headers=original).status_code, 201)
        new = subprocess.run(
            [*base, "rotate-token", principal], env=owner_env, check=True, capture_output=True, text=True
        )
        rotated = {"authorization": "Bearer " + new.stdout.strip()}
        self.assertEqual(self.client.get(self.path, headers=original).status_code, 401)
        self.assertEqual(self.client.get(self.path, headers=rotated).status_code, 200)
        self.assertEqual(
            self.client.put(
                self.path + "/completion", json=self.end | {"chunk_count": 0}, headers=rotated
            ).status_code,
            202,
        )
        subprocess.run([*base, "revoke-token", principal], env=owner_env, check=True, capture_output=True)
        self.assertEqual(self.client.get(self.path, headers=rotated).status_code, 401)

    def test_trusted_proxy_boundary(self):
        from unittest.mock import patch

        from starlette.requests import Request

        from server.access import Problem, source_address

        scope = {
            "type": "http",
            "scheme": "http",
            "server": ("192.0.2.1", 443),
            "path": "/",
            "query_string": b"",
            "client": ("192.0.2.2", 1000),
            "headers": [(b"x-forwarded-for", b"2001:db8::4"), (b"x-forwarded-proto", b"https")],
        }
        with patch.dict(os.environ, VIPNET_TRUSTED_PROXIES="192.0.2.2/32"):
            self.assertEqual(source_address(Request(scope)), "2001:db8::4")
            with self.assertRaises(Problem):
                source_address(Request(scope | {"headers": scope["headers"] + [scope["headers"][0]]}))
        with patch.dict(os.environ, VIPNET_TRUSTED_PROXIES=""):
            with self.assertRaises(Problem):
                source_address(Request(scope))

    def test_scopes_and_source(self):
        bad = self.client.put(self.path, json=self.opening, headers={"authorization": ""})
        self.assertEqual(bad.status_code, 401)
        self.assertEqual(
            self.client.put(
                self.path,
                json=self.opening,
                headers={"x-forwarded-for": "192.0.2.88", "x-forwarded-proto": "http"},
            ).status_code,
            201,
        )
        other = {"authorization": "Bearer " + os.environ["TEST_OTHER"]}
        operator = {"authorization": "Bearer " + os.environ["TEST_READER"]}
        self.assertEqual(self.client.get(self.path, headers=other).status_code, 404)
        self.assertEqual(self.client.get(self.path, headers=operator).status_code, 200)
        self.assertEqual(
            self.client.put(self.path + "/completion", json=self.end, headers=operator).status_code, 403
        )
        self.assertNotIn(
            self.sid, [s["session_id"] for s in self.client.get("sessions", headers=other).json()]
        )
        other_id = str(uuid4())
        foreign = "sessions/" + other_id
        self.assertEqual(
            self.client.put(foreign, json=self.opening | {"session_id": other_id}, headers=other).status_code,
            201,
        )
        self.assertEqual(self.client.get(foreign, headers=operator).status_code, 404)
        self.assertEqual(
            self.client.put(
                foreign + "/completion", json=self.end | {"chunk_count": 0}, headers=other
            ).status_code,
            202,
        )
        with psycopg.connect(os.environ["TEST_OWNER_DSN"]) as db:
            peer = db.execute("SELECT host(source_ip) FROM core.session WHERE id=%s", (self.sid,)).fetchone()[
                0
            ]
        self.assertEqual(peer, "127.0.0.1")
        self.assertEqual(self.finish(chunk_count=0, state="failed").status_code, 202)

    def test_wire_limits_and_contract(self):
        self.open()
        url = self.path + "/chunks/0"
        headers = {"content-type": "application/json", "content-encoding": "gzip"}
        self.assertEqual(
            self.client.put(
                url, content=gzip.compress(b" " * (1024 * 1024 + 1)), headers=headers
            ).status_code,
            413,
        )
        self.assertEqual(
            self.client.put(url, content=b"x" * (256 * 1024 + 1), headers=headers).status_code, 413
        )
        self.assertEqual(self.client.put(url, content=b"bad", headers=headers).status_code, 422)
        self.assertEqual(self.chunk(0, [self.sample() | {"session_id": str(uuid4())}]).status_code, 422)
        self.assertEqual(self.chunk(0, [self.sample() | {"ttl": 0}]).status_code, 422)
        raw = json.dumps({"schema_version": 1, "samples": [self.sample()]}).encode()
        self.assertEqual(self.client.put(url, content=gzip.compress(raw), headers=headers).status_code, 204)
        self.assertEqual(
            self.client.put(url, content=raw, headers={"content-type": "application/json"}).status_code, 204
        )
        self.assertEqual(
            self.client.put(
                url, content=raw + b" ", headers={"content-type": "application/json"}
            ).status_code,
            409,
        )
        self.assertEqual(self.finish().status_code, 202)
        self.assertEqual(self.client.get("openapi.json").json()["openapi"], "3.1.0")

    def test_idle_close_and_retention(self):
        from unittest.mock import patch

        from server.database import engine
        from server.maintenance import maintain

        self.open()
        with psycopg.connect(os.environ["TEST_OWNER_DSN"]) as db:
            db.execute("UPDATE core.session SET touched_at=now()-interval '3 weeks' WHERE id=%s", (self.sid,))
            db.execute(
                "CREATE TABLE mtr.p20000101 PARTITION OF mtr.sample FOR VALUES FROM ('2000-01-01') TO ('2000-01-02')"
            )
        engine.cache_clear()
        try:
            with patch.dict(os.environ, VIPNET_DATABASE_URL=os.environ["TEST_OWNER_URL"]):
                maintain()
        finally:
            engine().dispose()
            engine.cache_clear()
        self.assertEqual(self.client.get(self.path).json()["state"], "partial")
        with psycopg.connect(os.environ["TEST_OWNER_DSN"]) as db:
            self.assertIsNone(db.execute("SELECT to_regclass('mtr.p20000101')").fetchone()[0])
            self.assertEqual(
                db.execute(
                    "SELECT count(*) FROM diagnostics.job WHERE session_id=%s", (self.sid,)
                ).fetchone()[0],
                1,
            )
