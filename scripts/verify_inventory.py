"""Qualify the Windows inventory on the local machine. Keep detailed data in private output."""

import argparse
import hashlib
import json
import os
import platform
import sqlite3
import subprocess
import sys
import tempfile
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from contracts.test_contracts import validator


def capture(exe, queue):
    env = dict(os.environ, VIPNET_QUEUE_DIR=str(queue))
    env.pop("VIPNET_TOKEN", None)
    env.pop("VIPNET_API_ORIGIN", None)
    result = subprocess.run([exe, "--inventory"], capture_output=True, env=env, timeout=35, check=True)
    doc = json.loads(result.stdout)
    validator("session.schema.json").validate(doc)
    with closing(sqlite3.connect(queue / "queue.sqlite3")) as db:
        opened, ended = db.execute(
            "SELECT opening,ending FROM session WHERE id=?", (doc["session_id"],)
        ).fetchone()
        assert json.loads(opened) == doc and json.loads(ended)["state"] == "completed"
    return doc


def identities(doc):
    return {
        r["id"]: r["mac_id"]["value"]
        for r in doc["inventory"]["interfaces"].get("value", [])
        if r["mac_id"]["status"] == "ok"
    }


def check(exe, evidence):
    evidence.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="vipnet-inventory-") as scratch:
        queue = Path(scratch) / "one"
        a = capture(exe, queue)
        b = capture(exe, queue)
        c = capture(exe, Path(scratch) / "two")
        first, second, other = map(identities, (a, b, c))
        common = first.keys() & second.keys() & other.keys()
        assert common and all(first[k] == second[k] and first[k] != other[k] for k in common)
        doc = b["inventory"]
        assert doc["system"]["windows"]["value"] == platform.version()
        assert doc["system"]["memory"]["value"]["total_bytes"] > 0
        assert doc["captured_at"] <= doc["finished_at"]
        # Compare against Windows management providers without exporting their identifiers.
        script = """$ErrorActionPreference='Stop'
        [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
        $adapters=@(Get-NetAdapter -IncludeHidden | Where-Object Status -eq 'Up' | Select-Object ifIndex,ReceiveLinkSpeed,TransmitLinkSpeed)
        $ips=@(Get-NetIPAddress -AddressFamily IPv4 | Select-Object -ExpandProperty IPAddress)
        $ram=(Get-CimInstance Win32_OperatingSystem).TotalVisibleMemorySize
        [pscustomobject]@{active=$adapters;ips=$ips;ram_kib=$ram}|ConvertTo-Json -Compress"""
        ref = json.loads(
            subprocess.check_output(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", script], timeout=45
            )
        )
        interfaces = doc["interfaces"]["value"]
        reference = {r["ifIndex"]: r for r in ref["active"]}
        assert set(reference) & {r["index"] for r in interfaces if r["oper_status"] == 1}
        speed_matches = sum(r["index"] in reference and r["link"].get("value") == {
            "rx_bps": reference[r["index"]]["ReceiveLinkSpeed"],
            "tx_bps": reference[r["index"]]["TransmitLinkSpeed"]} for r in interfaces)

        ips = {u["ip"] for nic in interfaces for u in nic["unicast"]["value"]}
        assert (set(ref["ips"]) & ips) - {"127.0.0.1"}
        assert abs(ref["ram_kib"] * 1024 - doc["system"]["memory"]["value"]["total_bytes"]) < 1024 * 1024
        # Record an explicit synthetic prior observation only in this disposable queue.
        with closing(sqlite3.connect(queue / "queue.sqlite3")) as db:
            db.execute("UPDATE gateway_seen SET mac=?,observed=?", ("0" * 64, "2000-01-01T00:00:00.000Z"))
            simulated = db.total_changes
            db.commit()
        if simulated:
            changes = capture(exe, queue)["inventory"]["gateway_changes"].get("value", [])
            assert changes and all(r["previous_mac_id"] == "0" * 64 for r in changes)
        raw = evidence / "inventory-private.json"
        raw.write_bytes(json.dumps(b, ensure_ascii=False).encode("utf-8"))
        summary = {
            "binary_version": b["client_version"],
            "exe_sha256": hashlib.sha256(exe.read_bytes()).hexdigest(),
            "raw_sha256": hashlib.sha256(raw.read_bytes()).hexdigest(),
            "windows": platform.platform(),
            "started_utc": doc["captured_at"],
            "finished_utc": doc["finished_at"],
            "scope": "local Windows APIs, passive neighbor cache",
            "counter_window_min_ms": 500,
            "interfaces": len(interfaces),
            "up": sum(r["oper_status"] == 1 for r in interfaces),
            "reference_link_speed_matches": speed_matches,
            "logical_processors": doc["system"]["logical_processors"],
            "visible_ram_bytes": doc["system"]["memory"]["value"]["total_bytes"],
            "drivers_read": sum(r["driver"]["status"] == "ok" for r in interfaces),
            "known_link_speeds": sum(r["link"]["status"] == "ok" for r in interfaces),
            "traffic_samples": sum(r["traffic"]["status"] == "ok" for r in interfaces),
            "routes": len(doc["routes"].get("value", [])),
            "neighbors": len(doc["neighbors"].get("value", [])),
            "unique_macs": doc["unique_neighbor_macs"],
            "oui_matches": sum(r["vendor"]["status"] == "ok" for r in doc["neighbors"].get("value", [])),
            "wifi_status": doc["wifi"]["status"],
            "radios": [
                {"status": r["connection"]["status"], "rssi_dbm": r["rssi_dbm"], "channel":r["channel"],
                 "phy":r["connection"].get("value",{}).get("phy")}
                for r in doc["wifi"].get("value", [])
            ],
            "observed_duplicate_ips": len(doc["duplicate_addresses"].get("value", [])),
            "observed_gateway_changes": len(doc["gateway_changes"].get("value", [])),
            "pseudonyms_stable_and_isolated": True,
            "windows_reference": "adapter index, IPv4, visible RAM matched",
            "synthetic_prior_gateway_test": "passed" if simulated else "no observed gateway",
            "completed_utc": datetime.now(UTC).isoformat(),
        }
        (evidence / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(summary))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("exe", type=Path)
    parser.add_argument("private_dir", type=Path)
    args = parser.parse_args()
    check(args.exe.resolve(strict=True), args.private_dir.resolve())
