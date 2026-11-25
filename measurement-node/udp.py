"""One-way bounded UDP delivery check, authorized over an mTLS connection."""

import argparse
import hashlib
import json
import os
import secrets
import socket
import ssl
import time
from datetime import UTC, datetime
from ipaddress import ip_address
from pathlib import Path
from uuid import UUID

from reverse import server_context

COUNT, SIZE, INTERVAL = 10, 1200, 0.1


def receive(bind, port, expected, sid, fingerprint, cert, key, ca):
    family = socket.AF_INET6 if bind.version == 6 else socket.AF_INET
    ctx = server_context(cert, key, ca)
    with socket.socket(family) as listener, socket.socket(family, socket.SOCK_DGRAM) as udp:
        listener.bind((str(bind), port))
        listener.settimeout(30)
        listener.listen(1)
        udp.bind((str(bind), port))
        raw, address = listener.accept()
        with raw:
            if ip_address(address[0]) != expected:
                raise ValueError("unexpected source")
            raw.settimeout(5)
            with ctx.wrap_socket(raw, server_side=True) as channel, channel.makefile("rb") as stream:
                observed = hashlib.sha256(channel.getpeercert(binary_form=True)).hexdigest()
                if observed != fingerprint.lower() or stream.readline(39) != (str(sid) + "\n").encode():
                    raise ValueError("unauthorized session")
                nonce = secrets.token_bytes(24)
                channel.sendall(nonce.hex().encode() + b"\n")
                started = datetime.now(UTC).isoformat()
                deadline = time.monotonic() + 3
                received = {}
                while len(received) < COUNT and time.monotonic() < deadline:
                    udp.settimeout(max(0.001, deadline - time.monotonic()))
                    try:
                        msg, peer = udp.recvfrom(SIZE + 1)
                    except TimeoutError:
                        break
                    if (ip_address(peer[0]) == expected and len(msg) == SIZE and
                            msg.startswith(nonce) and msg[24] < COUNT):
                        received.setdefault(msg[24], datetime.now(UTC).isoformat())
                report = dict(session_id=str(sid), started_utc=started, completed_utc=datetime.now(UTC).isoformat(),
                              expected=COUNT, received=len(received), datagram_bytes=SIZE,
                              interval_ms=100, arrivals_utc=received, peer=str(expected))
                channel.sendall(json.dumps(report).encode() + b"\n")
                return report


def send(target, port, name, sid, cert, key, ca):
    ctx = ssl.create_default_context(cafile=ca)
    ctx.load_cert_chain(cert, key)
    family = socket.AF_INET6 if target.version == 6 else socket.AF_INET
    with socket.create_connection((str(target), port), timeout=6) as raw, ctx.wrap_socket(raw, server_hostname=name) as ch:
        with ch.makefile("rb") as stream, socket.socket(family, socket.SOCK_DGRAM) as udp:
            udp.bind((ch.getsockname()[0], 0))
            ch.sendall((str(sid) + "\n").encode())
            nonce = bytes.fromhex(stream.readline(50).decode().strip())
            if len(nonce) != 24:
                raise ValueError("invalid session nonce")
            for i in range(COUNT):
                msg = nonce + bytes([i]) + os.urandom(SIZE - 25)
                if udp.sendto(msg, (str(target), port)) != SIZE:
                    raise OSError("short datagram")
                time.sleep(INTERVAL)
            report = json.loads(stream.readline(4096))
            if report["session_id"] != str(sid) or report["expected"] != COUNT:
                raise ValueError("result session mismatch")
            return report


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="mode", required=True)
    node, client = sub.add_parser("receive"), sub.add_parser("send")
    for cmd in (node, client):
        cmd.add_argument("ip", type=ip_address)
        cmd.add_argument("port", type=int)
        cmd.add_argument("session", type=UUID)
        for flag in ("cert", "key", "ca", "output"):
            cmd.add_argument("--"+flag, type=Path, required=True)
    node.add_argument("--peer", type=ip_address, required=True)
    node.add_argument("--client-sha256", required=True)
    client.add_argument("--name", required=True)
    a = p.parse_args()
    if a.ip.is_multicast or a.ip.is_unspecified or not 1 <= a.port <= 65535:
        p.error("unicast endpoint and valid port required")
    with a.output.open("x", encoding="utf-8") as out:
        if a.mode == "receive":
            result = receive(a.ip, a.port, a.peer, a.session, a.client_sha256, a.cert, a.key, a.ca)
        else:
            result = send(a.ip, a.port, a.name, a.session, a.cert, a.key, a.ca)
        json.dump(result, out, indent=2)
        out.write("\n")
