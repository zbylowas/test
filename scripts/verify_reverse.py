"""Exercise a mutually authenticated reverse run using a temporary CA on loopback."""

import argparse
import json
import socket
import ssl
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import UTC, datetime, timedelta
from importlib import import_module
from ipaddress import ip_address
from pathlib import Path
from uuid import UUID

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
reverse = import_module("measurement-node.reverse")
from rules.report import report


def certs(directory, node_ip="127.0.0.1"):
    now = datetime.now(UTC)

    def identity(name, role=None, issuer=None):
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        ca, signer = issuer if issuer else (None, key)
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca.subject if ca else subject)
            .serial_number(x509.random_serial_number())
            .public_key(key.public_key())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(minutes=15))
            .add_extension(x509.BasicConstraints(ca=issuer is None, path_length=None), critical=True)
        )
        if role:
            builder = builder.add_extension(x509.ExtendedKeyUsage([role]), critical=False)
        if role == ExtendedKeyUsageOID.SERVER_AUTH:
            builder = builder.add_extension(
                x509.SubjectAlternativeName([x509.IPAddress(ip_address(node_ip))]), critical=False
            )
        cert = builder.sign(signer, hashes.SHA256())
        (directory / (name + ".pem")).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        if role:
            (directory / (name + ".key")).write_bytes(
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )
        return cert, key

    ca = identity("ca")
    identity("node", ExtendedKeyUsageOID.SERVER_AUTH, ca)
    identity("client", ExtendedKeyUsageOID.CLIENT_AUTH, ca)


def qualify(exe, evidence):
    from wan_client import prepare, request

    sid = UUID(prepare(exe, "127.0.0.1", evidence))
    path = evidence / "forward.ndjson"
    with tempfile.TemporaryDirectory() as temp:
        d = Path(temp)
        certs(d)
        ctx = reverse.server_context(d / "node.pem", d / "node.key", d / "ca.pem")
        client = ssl.create_default_context(cafile=d / "ca.pem")
        fingerprint = (
            x509.load_pem_x509_certificate((d / "client.pem").read_bytes()).fingerprint(hashes.SHA256()).hex()
        )
        for scenario in ("no-client-cert", "wrong-session", "wrong-identity", "verified"):
            if scenario == "wrong-session":
                client.load_cert_chain(d / "client.pem", d / "client.key")
            with closing(socket.socket()) as sock, ThreadPoolExecutor(1) as pool:
                sock.bind(("127.0.0.1", 0))
                sock.listen(1)
                dest = evidence / scenario
                allowed = "0" * 64 if scenario == "wrong-identity" else fingerprint
                job = pool.submit(
                    reverse.measure, sock, ctx, ip_address("127.0.0.1"), allowed, sid, exe, dest
                )
                if scenario == "verified":
                    assert request(
                        evidence,
                        "127.0.0.1",
                        sock.getsockname()[1],
                        d / "client.pem",
                        d / "client.key",
                        d / "ca.pem",
                    ) == str(sid)
                    job.result()
                    continue
                try:
                    with (
                        socket.create_connection(sock.getsockname(), timeout=8) as c,
                        client.wrap_socket(c, server_hostname="127.0.0.1") as tls,
                    ):
                        message = str(sid) if scenario != "wrong-session" else str(UUID(int=0))
                        tls.sendall((message + "\n").encode("ascii"))
                        with tls.makefile("rb") as reader:
                            result = reader.readline()
                        assert result != b"completed\n"
                except OSError:
                    pass
                try:
                    job.result()
                except (ValueError, ssl.SSLError):
                    assert not dest.exists()
                else:
                    raise AssertionError("unauthorized reverse measurement")
        outcome = report(path, reverse_dir=evidence / "verified")["reverse"]
        assert outcome == {"status": "compared", "findings": []}
        summary = {
            "source": "127.0.0.1",
            "node": "127.0.0.1",
            "reverse_samples": 5,
            "forward_samples": 5,
            "invalid_client": "rejected",
            "wrong_session": "rejected",
            "wrong_identity": "rejected",
            "comparison": outcome,
        }
        (evidence / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(summary))


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("exe", type=Path)
    p.add_argument("evidence", type=Path)
    a = p.parse_args()
    qualify(a.exe.resolve(strict=True), a.evidence.resolve())
