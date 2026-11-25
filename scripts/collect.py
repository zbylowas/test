"""Collect three real Windows runs and numeric reference traces into a fresh directory."""
import argparse
import ctypes
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
from collections import Counter


def run_probe(binary, directory, label, targets, args):
    command = [str(binary), str(args.attempts), str(args.hops), str(args.timeout_ms), *targets]
    env = dict(os.environ, VIPNET_QUEUE_DIR=str(directory.resolve() / "queue"))
    env.pop("VIPNET_API_ORIGIN", None)
    env.pop("VIPNET_TOKEN", None)
    result = subprocess.run(command, capture_output=True, check=True, timeout=180, env=env)
    raw = directory / f"{label}.ndjson"
    raw.write_bytes(result.stdout)
    counters = json.loads(result.stderr)
    rows = [json.loads(line) for line in result.stdout.splitlines()]
    breakdown = {}
    for target in targets:
        selected = [r for r in rows if r["target"] == target]
        breakdown[target] = {
            "samples": len(selected),
            "statuses": dict(Counter(r["status"] for r in selected)),
            "codes": dict(Counter(r["native_code"] for r in selected)),
            "destination_ttls": [r["ttl"] for r in selected if r["status"] == "echo_reply"
                                 and r["responder"] == target],
        }
    return {"resources": counters, "targets": breakdown,
            "sha256": hashlib.sha256(raw.read_bytes()).hexdigest()}


def tcp_capabilities():
    # Only local TCP endpoints. Record effective privilege and raw socket creation separately.
    info = {"admin_token": bool(ctypes.windll.shell32.IsUserAnAdmin())}
    for label, family, ip, level, option, proto in (
        ("ipv4", socket.AF_INET, "127.0.0.1", socket.IPPROTO_IP, socket.IP_TTL, socket.IPPROTO_ICMP),
        ("ipv6", socket.AF_INET6, "::1", socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, socket.IPPROTO_ICMPV6),
    ):
        item = {}
        try:
            with socket.socket(family, socket.SOCK_STREAM) as server, socket.socket(family, socket.SOCK_STREAM) as client:
                server.settimeout(1)
                client.settimeout(1)
                server.bind((ip, 0))
                server.listen(1)
                client.setsockopt(level, option, 1)
                client.connect(server.getsockname())
                peer, _ = server.accept()
                peer.close()
                item["tcp_connect_hop_limit"] = client.getsockopt(level, option)
        except OSError as exc:
            item["tcp_error"] = exc.winerror
        try:
            with socket.socket(family, socket.SOCK_RAW, proto):
                item["raw_icmp_open"] = True
        except OSError as exc:
            item["raw_icmp_open"] = False
            item["raw_error"] = exc.winerror
        info[label] = item
    return info


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--targets", nargs=2, default=["127.0.0.1", "::1"], type=ipaddress.ip_address)
    parser.add_argument("--attempts", type=int, choices=range(1, 6), default=5)
    parser.add_argument("--hops", type=int, choices=range(1, 17), default=4)
    parser.add_argument("--timeout-ms", type=int, choices=range(100, 1001), default=400)
    args = parser.parse_args()
    targets = [str(ipaddress.ip_address(t)) for t in args.targets]
    if sys.platform != "win32" or targets[0] == targets[1]:
        parser.error("Windows and two distinct unicast targets required")
    args.directory.mkdir(parents=True, exist_ok=False)
    binary = args.binary.resolve(strict=True)
    evidence = {"exe_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                "windows_build": sys.getwindowsversion().build,
                "attempts": args.attempts, "max_hops": args.hops, "timeout_ms": args.timeout_ms, "runs": {}}
    for label, group in (("serial-a", targets[:1]), ("serial-b", targets[1:]), ("parallel", targets)):
        evidence["runs"][label] = run_probe(binary, args.directory, label, group, args)
    evidence["tcp"] = tcp_capabilities()
    evidence["reference_exit_codes"] = {}
    system32 = Path(os.environ["SystemRoot"]) / "System32"
    encoding = f"cp{ctypes.windll.kernel32.GetOEMCP()}"
    for index, target in enumerate(targets):
        for name, flags in (("tracert", ["-d", "-h", str(args.hops)]), ("ping", ["-n", "3"])):
            family = "-6" if ":" in target else "-4"
            command = [str(system32 / f"{name}.exe"), family, *flags, "-w", str(args.timeout_ms), target]
            result = subprocess.run(command, capture_output=True, timeout=150)
            label = f"{name}-{index + 1}"
            (args.directory / f"{label}.txt").write_text(
                (result.stdout + result.stderr).decode(encoding, errors="replace"), encoding="utf-8", newline="")
            evidence["reference_exit_codes"][label] = result.returncode
    summary = json.dumps(evidence, indent=2, ensure_ascii=False)
    (args.directory / "summary.json").write_text(summary + "\n", encoding="utf-8")
    print(summary)


if __name__ == "__main__":
    main()
