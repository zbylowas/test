"""Send one prepared session UUID over mTLS to the designated reverse MTR node."""

import argparse
import hashlib
import json
import os
import socket
import ssl
import subprocess
from ipaddress import ip_address
from pathlib import Path
from uuid import UUID


def prepare(exe, target, directory):
    ip = ip_address(target)
    if ip.is_unspecified or ip.is_multicast or ip.is_link_local:
        raise ValueError("a unicast measurement node is required")
    directory.mkdir(parents=True, exist_ok=False)
    env = dict(os.environ, VIPNET_QUEUE_DIR=str(directory / "queue"))
    env.pop("VIPNET_API_ORIGIN", None)
    env.pop("VIPNET_TOKEN", None)
    with (directory / "forward.ndjson").open("wb") as raw, (directory / "process.log").open("wb") as log:
        subprocess.run(
            [exe, "5", "16", "400", str(ip)], stdout=raw, stderr=log, timeout=90, check=True, env=env
        )
    data = (directory / "forward.ndjson").read_bytes()
    rows = [json.loads(line) for line in data.splitlines()]
    sessions = {str(UUID(r["session_id"])) for r in rows}
    if len(sessions) != 1 or any(ip_address(r["target"]) != ip for r in rows):
        raise ValueError("invalid forward measurement")
    session = sessions.pop()
    request = {
        "scope": "loopback" if ip.is_loopback else "routed_target",
        "session": session,
        "node": str(ip),
        "forward_sha256": hashlib.sha256(data).hexdigest(),
        "exe_sha256": hashlib.sha256(exe.read_bytes()).hexdigest(),
        "version": subprocess.check_output([exe, "--version"]).decode().strip(),
        "rounds": 5,
        "max_ttl": 16,
        "timeout_ms": 400,
        "first_sample_utc": rows[0]["timestamp"],
        "last_sample_utc": rows[-1]["timestamp"],
    }
    (directory / "request.json").write_text(json.dumps(request, indent=2) + "\n", encoding="utf-8")
    return session


def request(directory, name, port, cert, key, ca=None):
    prepared = json.loads((directory / "request.json").read_text(encoding="utf-8"))
    data = (directory / "forward.ndjson").read_bytes()
    if hashlib.sha256(data).hexdigest() != prepared["forward_sha256"]:
        raise ValueError("forward file changed")
    node = str(ip_address(prepared["node"]))
    session = str(UUID(prepared["session"]))
    context = ssl.create_default_context(cafile=ca)
    context.load_cert_chain(cert, key)
    with (
        socket.create_connection((node, port), timeout=8) as sock,
        context.wrap_socket(sock, server_hostname=name) as tls,
    ):
        tls.settimeout(100)
        tls.sendall((session + "\n").encode("ascii"))
        with tls.makefile("rb") as stream:
            if stream.readline(32) != b"completed\n":
                raise ValueError("node did not acknowledge the reverse measurement")
    return session


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    prep = sub.add_parser("prepare")
    prep.add_argument("exe", type=Path)
    prep.add_argument("target")
    prep.add_argument("private_dir", type=Path)
    send = sub.add_parser("request")
    send.add_argument("private_dir", type=Path)
    send.add_argument("--server-name", required=True)
    send.add_argument("--port", type=int, required=True)
    send.add_argument("--cert", type=Path, required=True)
    send.add_argument("--key", type=Path, required=True)
    send.add_argument("--ca", type=Path)
    args = parser.parse_args()
    if args.action == "prepare":
        print(prepare(args.exe.resolve(strict=True), args.target, args.private_dir.resolve()))
    else:
        print(request(args.private_dir, args.server_name, args.port, args.cert, args.key, args.ca))
