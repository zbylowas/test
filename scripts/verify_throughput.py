"""Run the release client offline, then verify the acknowledged document on authorized staging."""

import argparse
import hashlib
import json
import os
import platform
import sqlite3
import ssl
import subprocess
import sys
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from contracts.test_contracts import validator
from rules.throughput import interpret


def qualify(exe, directory):
    directory.mkdir(parents=True, exist_ok=False)
    queue = directory / "queue"
    env = dict(os.environ, VIPNET_QUEUE_DIR=str(queue))
    origin = env["VIPNET_API_ORIGIN"].rstrip("/")
    headers = {"Authorization": "Bearer " + env["VIPNET_TOKEN"]}
    offline = {k: v for k, v in env.items() if k not in {"VIPNET_API_ORIGIN", "VIPNET_TOKEN"}}
    run = subprocess.run([exe, "--throughput"], capture_output=True, env=offline, timeout=210)
    (directory / "measurement-private.ndjson").write_bytes(run.stdout)
    (directory / "resources.json").write_bytes(run.stderr)
    rows = [json.loads(line) for line in run.stdout.splitlines()]
    doc = rows.pop()
    validator("throughput.schema.json").validate(doc)
    if run.returncode or doc["error"]:
        raise RuntimeError(f"native measurement failed: {doc['error']}, "
                           f"{[x['reason'] for x in doc['transfers'].values()]}")
    sid = doc["session_id"]
    assert all(row["session_id"] == sid for row in rows)
    assert {row["phase"] for row in rows} == set(doc["phases"])
    with closing(sqlite3.connect(queue / "queue.sqlite3")) as db:
        opening, ending = db.execute("SELECT opening,ending FROM session WHERE id=?", (sid,)).fetchone()
        assert json.loads(opening)["throughput"] == doc
        assert json.loads(ending)["state"] == "completed"
    subprocess.run([exe, "--sync"], capture_output=True, env=env, check=True, timeout=60)
    with closing(sqlite3.connect(queue / "queue.sqlite3")) as db:
        assert db.execute("SELECT count(*) FROM session").fetchone() == (0,)
    with httpx.Client(verify=ssl.create_default_context(), trust_env=False, headers=headers) as client:
        response = client.get(f"{origin}/api/v1/sessions/{sid}/throughput")
        response.raise_for_status()
        result = response.json()
    assert result["throughput"] == doc and result["session_id"] == sid.lower()
    analysis = result["interpretation"]
    assert analysis == interpret(doc)
    for name in ("download", "upload"):
        assert doc["profile"]["bytes"] == doc["transfers"][name]["client_bytes"] == doc["transfers"][name]["node_bytes"]
        assert analysis["directions"][name]["goodput_mbps"] > 0
        assert analysis["directions"][name]["median_increase_ms"] is not None
    summary = {"version": subprocess.check_output([exe, "--version"]).decode().strip(),
               "exe_sha256": hashlib.sha256(exe.read_bytes()).hexdigest(), "os": platform.platform(),
               "started_utc": doc["started_at"], "ended_utc": doc["ended_at"],
               "verified_utc": datetime.now(UTC).isoformat(), "node_id": doc["node_id"], "profile": doc["profile"],
               "transfers": doc["transfers"], "interpretation": analysis, "mtr": doc["mtr"],
               "mtr_samples_per_phase": {phase: sum(row["phase"] == phase for row in rows) for phase in doc["phases"]},
               "scope": "configured measurement origin; raw peer retained privately",
               "resources": json.loads(run.stderr), "raw_sha256": hashlib.sha256(run.stdout).hexdigest(),
               "queue_acknowledged": True, "database_api_equals_offline": True}
    (directory / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(analysis["directions"]))


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("exe", type=Path)
    p.add_argument("private_directory", type=Path)
    a = p.parse_args()
    qualify(a.exe.resolve(strict=True), a.private_directory.resolve())
