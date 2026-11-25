"""Manual, bounded qualification to the two published Cloudflare resolver addresses."""

import argparse
import hashlib
import ipaddress
import json
import locale
import os
import platform
import re
import subprocess
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from rules.mtr import interpret
from rules.report import load_rows

TARGETS = ["1.1.1.1", "2606:4700:4700::1111"]


def qualify(exe, directory):
    directory.mkdir(parents=True, exist_ok=False)
    env = dict(os.environ, VIPNET_QUEUE_DIR=str(directory / "queue"))
    env.pop("VIPNET_API_ORIGIN", None)
    env.pop("VIPNET_TOKEN", None)
    utc = lambda: datetime.now(UTC).isoformat()
    summary = {
        "start_utc": utc(),
        "version": subprocess.check_output([exe, "--version"]).decode().strip(),
        "exe_sha256": hashlib.sha256(exe.read_bytes()).hexdigest(),
        "windows": platform.platform(),
        "targets": TARGETS,
        "phase": "baseline",
        "rounds": 5,
        "max_ttl": 8,
        "timeout_ms": 400,
        "interval_ms": 150,
        "tcp_port": 443,
        "anonymization": "router addresses and raw traces retained only in the private directory",
    }
    proc = subprocess.run(
        [exe, "5", "8", "400", *TARGETS, "--protocol", "both", "--interval-ms", "150"],
        capture_output=True,
        env=env,
        timeout=240,
        check=True,
    )
    (directory / "field.ndjson").write_bytes(proc.stdout)
    rows = load_rows(proc.stdout)
    summary.update(
        measurements_sha256=hashlib.sha256(proc.stdout).hexdigest(),
        resources=json.loads(proc.stderr),
        series=[],
    )
    analysis = interpret(rows)
    for ip in TARGETS:
        fam = ipaddress.ip_address(ip).version
        ref = subprocess.run(
            ["tracert", "-" + str(fam), "-d", "-h", "8", "-w", "400", ip],
            capture_output=True,
            timeout=65,
            check=False,
        )
        (directory / f"tracert-v{fam}.txt").write_bytes(ref.stdout)
        reference = {}
        for line in ref.stdout.decode(locale.getpreferredencoding(False), errors="replace").splitlines():
            match = re.match(r"^\s*(\d+)\s+.*?\s+([0-9a-fA-F.:]+)\s*$", line)
            if match:
                try:
                    reference[int(match[1])] = str(ipaddress.ip_address(match[2]))
                except ValueError:
                    pass
        for item in analysis["series"]:
            if item["target"] != ip:
                continue
            protocol = item["protocol"]
            selected = [r for r in rows if r["target"] == ip and r["protocol"] == protocol]
            matches = [
                ttl
                for ttl, addr in reference.items()
                if addr in item["stats"].get(ttl, {}).get("responders", [])
            ]
            summary["series"].append(
                {
                    "target": ip,
                    "protocol": protocol,
                    "samples": len(selected),
                    "statuses": dict(Counter(r["status"] for r in selected)),
                    "native_codes": dict(Counter(r["native_code"] for r in selected)),
                    "end_ttls": [
                        r["ttl"]
                        for r in selected
                        if r["status"] in {"tcp_connected", "echo_reply"} and r["responder"] == ip
                    ],
                    "tracert_responding_ttls": sorted(reference),
                    "matched_tracert_ttls": matches,
                    "rules": [d["rule_id"] for d in item["findings"]],
                }
            )
    summary["completed_utc"] = utc()
    (directory / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary))


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("exe", type=Path)
    p.add_argument("private_dir", type=Path)
    a = p.parse_args()
    qualify(a.exe.resolve(strict=True), a.private_dir.resolve())
