"""Compare two single-target runs with the saved parallel field qualification."""

import argparse
import hashlib
import json
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from statistics import median

from field_v020 import TARGETS

from rules.report import load_rows


def compare(exe, directory):
    meta = json.loads((directory / "summary.json").read_text(encoding="utf-8"))
    raw = (directory / "field.ndjson").read_bytes()
    if (
        meta["targets"] != TARGETS
        or hashlib.sha256(exe.read_bytes()).hexdigest() != meta["exe_sha256"]
        or hashlib.sha256(raw).hexdigest() != meta["measurements_sha256"]
    ):
        raise ValueError("comparison input mismatch")
    parallel = load_rows(raw)
    runs = []
    output = directory / "serial"
    output.mkdir()
    env = dict(os.environ, VIPNET_QUEUE_DIR=str(output / "queue"))
    env.pop("VIPNET_API_ORIGIN", None)
    env.pop("VIPNET_TOKEN", None)
    for target in TARGETS:
        start = datetime.now(UTC).isoformat()
        proc = subprocess.run(
            [
                exe,
                str(meta["rounds"]),
                str(meta["max_ttl"]),
                str(meta["timeout_ms"]),
                target,
                "--protocol",
                "both",
                "--interval-ms",
                str(meta["interval_ms"]),
            ],
            capture_output=True,
            env=env,
            timeout=120,
            check=True,
        )
        path = output / ("ipv6.ndjson" if ":" in target else "ipv4.ndjson")
        path.write_bytes(proc.stdout)
        single = load_rows(proc.stdout)
        comparison = {}
        for protocol in ("icmp", "tcp"):
            for label, rows in (("serial", single), ("parallel", parallel)):
                arrived = [
                    r
                    for r in rows
                    if r["target"] == target
                    and r["protocol"] == protocol
                    and r["status"] in {"echo_reply", "tcp_connected"}
                    and r["responder"] == target
                ]
                comparison.setdefault(protocol, {})[label] = {
                    "arrivals": len(arrived),
                    "end_ttls": sorted({r["ttl"] for r in arrived}),
                    "end_median_ms": median(r["rtt_ms"] for r in arrived) if arrived else None,
                }
        runs.append(
            {
                "target": target,
                "start_utc": start,
                "end_utc": datetime.now(UTC).isoformat(),
                "sha256": hashlib.sha256(proc.stdout).hexdigest(),
                "resources": json.loads(proc.stderr),
                "comparison": comparison,
            }
        )
    (output / "summary.json").write_text(json.dumps(runs, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(runs))


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("exe", type=Path)
    p.add_argument("field_dir", type=Path)
    a = p.parse_args()
    compare(a.exe.resolve(strict=True), a.field_dir.resolve())
