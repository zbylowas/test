"""Coordinate four measurement windows with real loopback TCP traffic on Windows."""

import json
import socket
import subprocess
import threading
from contextlib import ExitStack, contextmanager, nullcontext


@contextmanager
def listening(ip):
    with socket.socket(socket.AF_INET6 if ":" in ip else socket.AF_INET) as sock:
        sock.bind((ip, 443))
        sock.listen()
        sock.settimeout(0.1)
        stop = threading.Event()

        def accept():
            while not stop.is_set():
                try:
                    conn, _ = sock.accept()
                except TimeoutError:
                    continue
                conn.close()

        thread = threading.Thread(target=accept)
        thread.start()
        try:
            yield
        finally:
            stop.set()
            thread.join()


@contextmanager
def load_window(phase):
    # Client/endpoint are separate TCP sockets. Limit to ~1.6 MiB/s for a bounded staging test.
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        with socket.create_connection(server.getsockname(), timeout=2) as client:
            peer, _ = server.accept()
            with peer:
                peer.settimeout(2)
                sender, receiver = (peer, client) if phase == "download" else (client, peer)
                stop, started = threading.Event(), threading.Event()
                evidence = {"bytes": 0}

                def transfer():
                    try:
                        block = bytes(16384)
                        while not stop.is_set():
                            sender.sendall(block)
                            remaining = len(block)
                            while remaining:
                                count = len(receiver.recv(remaining))
                                if not count:
                                    raise ConnectionError("load socket closed")
                                remaining -= count
                            evidence["bytes"] += len(block)
                            started.set()
                            stop.wait(0.01)
                    except OSError as error:
                        evidence["error"] = type(error).__name__

                worker = threading.Thread(target=transfer)
                worker.start()
                try:
                    assert started.wait(3)
                    yield evidence
                finally:
                    stop.set()
                    worker.join(5)
                assert not worker.is_alive() and "error" not in evidence


def capture(exe, env, evidence):
    traffic = {}
    raw = evidence / "loopback.ndjson"
    with ExitStack() as stack:
        for ip in ("127.0.0.1", "::1"):
            stack.enter_context(listening(ip))
        out = stack.enter_context(raw.open("wb"))
        args = [exe, "5", "2", "400", "127.0.0.1", "::1", "--protocol", "both", "--phase-control"]
        proc = stack.enter_context(
            subprocess.Popen(args, env=env, stdin=subprocess.PIPE, stdout=out, stderr=subprocess.PIPE)
        )
        watchdog = threading.Timer(40, proc.kill)
        watchdog.start()
        try:
            for phase, command in zip(("baseline", "download", "upload", "recovery"), b"BDUR"):
                with load_window(phase) if phase in ("download", "upload") else nullcontext() as traffic_info:
                    proc.stdin.write(bytes([command]))
                    proc.stdin.flush()
                    assert json.loads(proc.stderr.readline()) == {"phase_finished": phase}
                    if traffic_info:
                        traffic[phase] = traffic_info
            _, meta = proc.communicate(timeout=5)
            assert proc.returncode == 0
            resources = json.loads(meta)
        finally:
            watchdog.cancel()
            if proc.poll() is None:
                proc.kill()
                proc.wait()
    rows = [json.loads(line) for line in raw.read_bytes().splitlines()]
    assert len({(r["target"], r["protocol"], r["phase"], r["attempt"]) for r in rows}) == len(rows) == 80
    assert all(
        r["status"] == ("echo_reply" if r["protocol"] == "icmp" else "tcp_connected") and r["ttl"] == 1
        for r in rows
    )
    return {
        "protocols": ["icmp", "tcp/443"],
        "phases": ["baseline", "download", "upload", "recovery"],
        "load_bytes": {phase: info["bytes"] for phase, info in traffic.items()},
        "resources": resources,
    }
