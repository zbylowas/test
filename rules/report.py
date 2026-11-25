"""Reinterpret validated NDJSON offline, optionally with trusted operator context."""

import argparse
import hashlib
import json
from datetime import datetime, timedelta
from ipaddress import ip_address
from pathlib import Path
from uuid import UUID

from rules.mtr import VERSION, finding, interpret, stable_path
from server.wire import VALIDATORS


def load_rows(raw):
    rows = []
    for line in raw.splitlines():
        r = json.loads(line)
        VALIDATORS["mtr-sample"].validate(r)
        r["session_id"] = str(UUID(r["session_id"]))
        for key in ("responder", "target"):
            if r[key]:
                r[key] = str(ip_address(r[key]))
        rows.append(r)
    return rows


def compare_reverse(forward, reverse, pair):
    def series(rows, sid, target):
        if not rows or {r["session_id"] for r in rows} != {sid}:
            raise ValueError("reverse pair session mismatch")
        return [
            r for r in rows if r["target"] == target and r["protocol"] == "icmp" and r["phase"] == "baseline"
        ]

    f = series(forward, pair["forward_session"], pair["node"])
    r = series(reverse, pair["reverse_session"], pair["source"])
    if not f or not r:
        raise ValueError("reverse pair endpoint mismatch")
    # Both inputs must be valid individual series, including unique TTL/round keys.
    interpret(r)
    times = [datetime.fromisoformat(row["timestamp"]) for row in f + r]
    if max(times) - min(times) > timedelta(minutes=5):
        return {"status": "unavailable", "reason": "comparison_window_exceeded"}
    fp, rp = stable_path(f), stable_path(r)
    if fp is None or rp is None:
        return {"status": "unavailable", "reason": "incomplete_or_variable_path"}
    if fp == rp[::-1]:
        return {"status": "compared", "findings": []}
    diagnosis = finding(
        "route.possible_asymmetry",
        "info",
        "medium",
        {
            "forward": fp,
            "reverse": rp,
            "forward_session": pair["forward_session"],
            "reverse_session": pair["reverse_session"],
        },
        "Interfejsy tego samego routera mogą używać różnych adresów w obu kierunkach.",
        "Porównaj aliasy routerów i powtórz pomiar równocześnie.",
    )
    return {"status": "compared", "findings": [diagnosis]}


def report(path, networks=None, dual_stack_pair=None, reverse_dir=None):
    raw = path.read_bytes()
    rows = load_rows(raw)
    result = interpret(rows, networks, dual_stack_pair)
    result.update(rules_version=VERSION, input_sha256=hashlib.sha256(raw).hexdigest())
    if reverse_dir:
        pair = json.loads((reverse_dir / "pair.json").read_text(encoding="utf-8"))
        raw_reverse = (reverse_dir / "reverse.ndjson").read_bytes()
        if hashlib.sha256(raw_reverse).hexdigest() != pair["reverse_sha256"]:
            raise ValueError("reverse artifact checksum mismatch")
        result["reverse"] = compare_reverse(rows, load_rows(raw_reverse), pair)
    return result


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("ndjson", type=Path)
    p.add_argument(
        "--networks", type=Path, help="operator JSON object mapping router IP to verified network ID"
    )
    p.add_argument(
        "--dual-stack-pair", nargs=2, metavar=("V4", "V6"), help="operator-confirmed addresses of one service"
    )
    p.add_argument("--reverse-dir", type=Path, help="private artifact directly from the controlled node")
    args = p.parse_args()
    mapping = json.loads(args.networks.read_text(encoding="utf-8")) if args.networks else None
    print(
        json.dumps(
            report(args.ndjson, mapping, args.dual_stack_pair, args.reverse_dir),
            indent=2,
            ensure_ascii=True,
            allow_nan=False,
        )
    )
