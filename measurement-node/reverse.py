"""Run one bounded reverse MTR on a controlled Windows or Linux measurement node."""

import argparse
import hashlib
import json
import os
import platform
import socket
import ssl
import subprocess
from ipaddress import ip_address
from pathlib import Path
from uuid import UUID


def measure(listener, context, expected_peer, client_sha256, forward_session, exe, output):
    """The node operator authorizes the source and session before opening the listener."""
    listener.settimeout(30)
    conn, addr = listener.accept()
    with conn:
        conn.settimeout(5)
        peer = ip_address(addr[0])
        if peer != expected_peer:
            raise ValueError("unexpected source address")
        with context.wrap_socket(conn, server_side=True) as channel:
            # Authenticate the live peer and match the forward session on this TLS channel.
            identity = hashlib.sha256(channel.getpeercert(binary_form=True)).hexdigest()
            if identity != client_sha256.lower():
                raise ValueError("certificate does not match the authorized session")
            with channel.makefile("rb") as reader:
                if reader.readline(39) != (str(forward_session) + "\n").encode("ascii"):
                    raise ValueError("session mismatch")
            node = str(ip_address(channel.getsockname()[0]))
            output.mkdir(parents=True, exist_ok=False)
            env = dict(os.environ, VIPNET_QUEUE_DIR=str(output / "queue"))
            env.pop("VIPNET_TOKEN", None)
            env.pop("VIPNET_API_ORIGIN", None)
            with (output / "reverse.ndjson").open("wb") as raw, (output / "process.log").open("wb") as log:
                subprocess.run(
                    [exe, "5", "16", "400", str(peer)],
                    stdout=raw,
                    stderr=log,
                    env=env,
                    check=True,
                    timeout=90,
                )
            data = (output / "reverse.ndjson").read_bytes()
            rows = [json.loads(line) for line in data.splitlines()]
            sessions = {UUID(r["session_id"]) for r in rows}
            if len(sessions) != 1 or any(ip_address(r["target"]) != peer for r in rows):
                raise ValueError("inconsistent reverse measurement")
            metadata = {
                "forward_session": str(forward_session),
                "reverse_session": str(sessions.pop()),
                "source": str(peer),
                "node": node,
                "peer_cert_sha256": identity,
                "reverse_sha256": hashlib.sha256(data).hexdigest(),
                "exe_sha256": hashlib.sha256(exe.read_bytes()).hexdigest(),
                "version": subprocess.check_output([exe, "--version"], timeout=5).decode().strip(),
                "system": platform.platform(),
                "first_sample_utc": rows[0]["timestamp"],
                "last_sample_utc": rows[-1]["timestamp"],
                "rounds": 5,
                "ttl": 16,
                "timeout_ms": 400,
            }
            (output / "pair.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
            channel.sendall(b"completed\n")


def server_context(cert, key, client_ca):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cafile=client_ca)
    return ctx


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", type=ip_address, required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--peer", type=ip_address, required=True)
    parser.add_argument("--session", type=UUID, required=True)
    parser.add_argument("--client-sha256", required=True, help="authorized client leaf fingerprint in hex")
    for flag in ("exe", "cert", "key", "client-ca", "output"):
        parser.add_argument("--" + flag, type=Path, required=True)
    a = parser.parse_args()
    if a.bind.is_unspecified or a.bind.is_multicast or a.peer.is_unspecified or a.peer.is_multicast:
        parser.error("unicast bind and peer required")
    ctx = server_context(a.cert, a.key, a.client_ca)
    with socket.socket(socket.AF_INET6 if a.bind.version == 6 else socket.AF_INET) as listener:
        listener.bind((str(a.bind), a.port))
        listener.listen(1)
        measure(
            listener, ctx, a.peer, a.client_sha256, a.session, a.exe.resolve(strict=True), a.output.resolve()
        )
