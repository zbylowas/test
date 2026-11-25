#!/usr/bin/env python3
"""Linux iputils/traceroute adapter for the single-peer reverse MTR runner."""

import json
import os
import re
import subprocess
import sys
import time
from datetime import UTC, datetime
from ipaddress import ip_address
from uuid import uuid4


def sample(target, ttl):
    command = ["traceroute", f"-{target.version}", "-n", "-I", "-q", "1", "-N", "1",
               "-w", "0.4", "-f", str(ttl), "-m", str(ttl), str(target)]
    proc = subprocess.run(command, capture_output=True, text=True, env=dict(os.environ, LC_ALL="C"), timeout=2)
    if proc.returncode:
        return "unavailable", proc.returncode, None, None
    lines = [line.split() for line in proc.stdout.splitlines() if line.strip()]
    hops = [fields for fields in lines if fields[0] == str(ttl)]
    if len(hops) != 1:
        return "unavailable", 0, None, None
    fields = hops[0]
    if fields[1:] == ["*"]:
        return "timeout", 0, None, None
    match = re.fullmatch(r"(\S+)\s+([\d.]+)\s+ms(?:\s+(!\S+))?", " ".join(fields[1:]))
    if not match:
        return "unavailable", 0, None, None
    addr, rtt, indication = match.groups()
    responder = ip_address(addr)
    status = "unreachable" if indication else "echo_reply" if responder == target else "ttl_expired"
    return status, 0, str(responder), float(rtt)


def main(args):
    if args == ["--version"]:
        print("0.4.0")
        return
    if len(args) != 4 or args[:3] != ["5", "16", "400"]:
        raise SystemExit("expected the bounded reverse profile: 5 16 400 PEER")
    target = ip_address(args[3])
    if target.is_unspecified or target.is_multicast or target.is_link_local:
        raise SystemExit("a scoped unicast peer is required")
    sid = str(uuid4())
    for attempt in range(1, 6):
        for ttl in range(1, 17):
            start = time.monotonic()
            utc = datetime.now(UTC).isoformat()
            status, code, responder, rtt = sample(target, ttl)
            print(json.dumps(dict(schema_version=1, session_id=sid, timestamp=utc, target=str(target),
                                  family=target.version, protocol="icmp", phase="baseline", attempt=attempt,
                                  ttl=ttl, status=status, native_code=code, responder=responder, rtt_ms=rtt)), flush=True)
            time.sleep(max(0, start + 0.1 - time.monotonic()))
            if status in {"echo_reply", "unreachable", "unavailable"}:
                break


if __name__ == "__main__":
    main(sys.argv[1:])
