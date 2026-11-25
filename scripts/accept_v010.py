"""Private Windows staging and crash/replay/restore qualification. All listeners use loopback."""

import argparse
import hashlib
import http.server
import ipaddress
import json
import os
import platform
import secrets
import socket
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import ExitStack, closing, contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import httpx
import psycopg
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from psycopg import sql

ROOT = Path(__file__).resolve().parents[1]


def run(args, env=None, **kwargs):
    return subprocess.run(
        [str(a) for a in args], cwd=ROOT, env=env, check=True, capture_output=True, timeout=90, **kwargs
    )


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tls_leaf(directory):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(minutes=20))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(key, hashes.SHA256())
    )
    pem, private = directory / "loopback.pem", directory / "loopback.key"
    pem.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    private.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    der = directory / "loopback.cer"
    der.write_bytes(cert.public_bytes(serialization.Encoding.DER))
    return pem, private, der, cert.fingerprint(hashes.SHA1()).hex()


@contextmanager
def loopback_relay(listen_port, upstream_port, cert):
    # Only the dedicated fixture connects to this socket. Forward to one fixed TLS peer.
    # No payloads, IP addresses or tokens go to a third party.
    context = ssl.create_default_context(cafile=cert)
    with httpx.Client(verify=context, trust_env=False, follow_redirects=False) as upstream:

        class Relay(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_PUT(self):
                length = int(self.headers.get("Content-Length", "0"))
                if not self.path.startswith("/api/v1/sessions/") or not 0 < length <= 256 * 1024:
                    self.send_error(400)
                    return
                headers = {
                    k: self.headers[k]
                    for k in ("Authorization", "Content-Type", "Content-Encoding")
                    if k in self.headers
                }
                response = upstream.put(
                    f"https://127.0.0.1:{upstream_port}" + self.path,
                    content=self.rfile.read(length),
                    headers=headers,
                )
                self.send_response(response.status_code)
                if "Retry-After" in response.headers:
                    self.send_header("Retry-After", response.headers["Retry-After"])
                self.send_header("Content-Length", str(len(response.content)))
                self.end_headers()
                self.wfile.write(response.content)

        with http.server.ThreadingHTTPServer(("127.0.0.1", listen_port), Relay) as relay:
            thread = threading.Thread(target=relay.serve_forever, daemon=True)
            thread.start()
            try:
                yield
            finally:
                relay.shutdown()
                thread.join()


@contextmanager
def runner_trust(der, thumbprint):
    if os.getenv("RUNNER_ENVIRONMENT") != "github-hosted":
        raise RuntimeError("Machine trust is reserved for the disposable hosted CI runner.")
    tool = Path(os.environ["SystemRoot"]) / "System32/certutil.exe"
    run([tool, "-f", "-addstore", "Root", der])
    try:
        yield
    finally:
        run([tool, "-delstore", "Root", thumbprint])


@contextmanager
def cluster(pg, private):
    password = secrets.token_urlsafe(32)
    pw = private / "bootstrap.pw"
    pw.write_text(password, encoding="ascii")
    data = private / "pgdata"
    try:
        run(
            [
                pg / "initdb",
                "-D",
                data,
                "--no-locale",
                "--encoding=UTF8",
                "-A",
                "scram-sha-256",
                "--username=stageowner",
                "--pwfile",
                pw,
            ]
        )
    finally:
        pw.unlink(missing_ok=True)
    dbport = port()
    # PostgreSQL on Windows may retain inherited pipe handles after pg_ctl returns.
    with (private / "pg_ctl.log").open("wb") as log:
        subprocess.run(
            [
                pg / "pg_ctl",
                "-D",
                data,
                "-l",
                private / "pg.log",
                "-o",
                f"-h 127.0.0.1 -p {dbport}",
                "-w",
                "start",
            ],
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=log,
            check=True,
            timeout=60,
        )
    try:
        base = f"postgresql://stageowner:{password}@127.0.0.1:{dbport}/"
        with psycopg.connect(base + "postgres", autocommit=True) as db:
            db.execute("CREATE DATABASE internet_diagnostics")
            db.execute("CREATE DATABASE restored")
            api_pw, worker_pw = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            for role, secret in (("netdiag_api", api_pw), ("netdiag_worker", worker_pw)):
                db.execute(
                    sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(
                        sql.Identifier(role), sql.Literal(secret)
                    )
                )
        dsn = base + "internet_diagnostics"

        def url(role, pwd):
            return f"postgresql+psycopg://{role}:{pwd}@127.0.0.1:{dbport}/internet_diagnostics"

        yield dict(
            owner=dsn,
            restored=base + "restored",
            owner_url=url("stageowner", password),
            api_url=url("netdiag_api", api_pw),
            worker_url=url("netdiag_worker", worker_pw),
            pg_env=dict(PGHOST="127.0.0.1", PGPORT=str(dbport), PGUSER="stageowner", PGPASSWORD=password),
        )
    finally:
        run([pg / "pg_ctl", "-D", data, "-m", "fast", "-w", "stop"])


@contextmanager
def serve(api_port, cert, key, env, log, *, hostname="127.0.0.1", system_trust=False):
    with log.open("ab") as output:
        proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "server",
                "serve",
                "--port",
                str(api_port),
                "--cert",
                str(cert),
                "--key",
                str(key),
            ],
            cwd=ROOT,
            env=env,
            stdout=output,
            stderr=output,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        try:
            with httpx.Client(
                verify=ssl.create_default_context(cafile=None if system_trust else cert),
                trust_env=False,
                timeout=1,
            ) as client:
                for _ in range(100):
                    if proc.poll() is not None:
                        raise RuntimeError("API exited; see private api.log")
                    try:
                        res = client.get(f"https://{hostname}:{api_port}/api/v1/health")
                        if res.status_code == 200:
                            break
                    except httpx.TransportError:
                        pass
                    time.sleep(0.15)
                else:
                    raise RuntimeError("API readiness timed out; see private api.log")
            yield
        finally:
            if proc.poll() is None:
                run(["taskkill.exe", "/PID", str(proc.pid), "/T", "/F"])
            proc.wait(timeout=10)


def inspect_queue(directory, sql_text):
    with closing(sqlite3.connect(directory / "queue.sqlite3")) as db:
        return db.execute(sql_text).fetchall()


def qualify(pg, exe, evidence, disposable):
    now = datetime.now(timezone.utc)
    evidence.mkdir(parents=True, exist_ok=False)
    summary = {
        "utc": now.isoformat(),
        "windows": platform.platform(),
        "version": run([exe, "--version"]).stdout.decode().strip(),
        "exe_sha256": digest(exe),
        "postgres": run([pg / "postgres", "--version"]).stdout.decode().strip(),
        "targets": ["127.0.0.1", "::1"],
        "rounds": 5,
        "max_ttl": 2,
        "timeout_ms": 400,
    }
    with tempfile.TemporaryDirectory(prefix="vipnet-v010-") as temp, ExitStack() as stack:
        private = Path(temp)
        cert, key, der, thumbprint = tls_leaf(private)
        config = stack.enter_context(cluster(pg, private))
        owner_env = dict(os.environ, VIPNET_DATABASE_URL=config["owner_url"])
        run([sys.executable, "-m", "alembic", "-c", "server/alembic.ini", "upgrade", "v010"], owner_env)
        legacy, owner = uuid4(), uuid4()
        with psycopg.connect(config["owner"]) as db:
            db.execute(
                "INSERT INTO security.principal(id,tenant,role,token_hash) VALUES(%s,%s,'client',%s)",
                (owner, uuid4(), secrets.token_bytes(32)),
            )
            db.execute(
                """INSERT INTO core.session(id,owner_id,started_at,client_version,mode,source_ip,open_digest)
                       VALUES (%s,%s,now(),'0.1.0','portable','192.0.2.1',%s)""",
                (legacy, owner, secrets.token_bytes(32)),
            )
        run([sys.executable, "-m", "alembic", "-c", "server/alembic.ini", "upgrade", "v020"], owner_env)
        previous = uuid4()
        params = {
            "windows_version": "10.0.26200",
            "targets": ["192.0.2.1"],
            "attempts": 5,
            "max_ttl": 4,
            "interval_ms": 100,
            "timeout_ms": 400,
            "protocol": "icmp",
            "phase_control": False,
        }
        with psycopg.connect(config["owner"]) as db:
            db.execute(
                """INSERT INTO core.session(id,owner_id,started_at,client_version,mode,source_ip,open_digest,measurement)
                      VALUES (%s,%s,now(),'0.2.0','portable','192.0.2.1',%s,%s::jsonb)""",
                (previous, owner, secrets.token_bytes(32), json.dumps(params)),
            )
        run([sys.executable, "-m", "alembic", "-c", "server/alembic.ini", "upgrade", "head"], owner_env)
        with psycopg.connect(config["owner"]) as db:
            assert db.execute(
                "SELECT client_version,measurement FROM core.session WHERE id=%s", (legacy,)
            ).fetchone() == ("0.1.0", None)
            assert db.execute(
                "SELECT measurement,inventory FROM core.session WHERE id=%s", (previous,)
            ).fetchone() == (params, None)
        summary["existing_v020_session_after_upgrade"] = "preserved"
        summary["existing_v010_session_after_upgrade"] = "preserved"
        run([sys.executable, "-m", "alembic", "-c", "server/alembic.ini", "downgrade", "base"], owner_env)
        run([sys.executable, "-m", "alembic", "-c", "server/alembic.ini", "upgrade", "head"], owner_env)
        with psycopg.connect(config["owner"]) as db:
            db.execute((ROOT / "server/grants.sql").read_text(encoding="utf-8"))

        def issue(tenant, role):
            return (
                run([sys.executable, "-m", "server", "issue-token", tenant, role], owner_env)
                .stdout.decode()
                .strip()
            )

        tenant = str(uuid4())
        token = issue(tenant, "client")
        api_port = port()
        origin = f"https://127.0.0.1:{api_port}"
        tests = dict(
            os.environ,
            VIPNET_DATABASE_URL=config["worker_url"],
            TEST_API=origin,
            TEST_CERT=str(cert),
            TEST_OWNER_DSN=config["owner"],
            TEST_OWNER_URL=config["owner_url"],
            TEST_CLIENT=token,
            TEST_SIBLING=issue(tenant, "client"),
            TEST_OTHER=issue(str(uuid4()), "client"),
            TEST_READER=issue(tenant, "operator"),
        )
        qdir = private / "queue"
        env = dict(os.environ, VIPNET_QUEUE_DIR=str(qdir), VIPNET_API_ORIGIN=origin, VIPNET_TOKEN=token)
        # API deliberately offline. Each sample reaches SQLite before it reaches stdout.
        proc = run([exe, "5", "2", "400", "127.0.0.1", "::1"], env)
        (evidence / "loopback.ndjson").write_bytes(proc.stdout)
        rows = [json.loads(r) for r in proc.stdout.splitlines()]
        assert len(rows) == 10 and all(r["status"] == "echo_reply" for r in rows)
        sid = rows[0]["session_id"]
        pending = inspect_queue(qdir, "SELECT next,chunks,last_error FROM session")[0]
        assert pending[0:2] == (-1, 1) and pending[2] < 0, pending
        summary.update(
            offline_samples=len(rows),
            offline_error=pending[2],
            measurement_resources=json.loads(proc.stderr.splitlines()[0]),
            first_sample_utc=rows[0]["timestamp"],
            last_sample_utc=rows[-1]["timestamp"],
            measurements_sha256=digest(evidence / "loopback.ndjson"),
        )
        # Kill a second process between committed samples. Recovery must seal it as partial.
        child = subprocess.Popen(
            [exe, "20", "2", "400", "::1"], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        try:
            first = json.loads(child.stdout.readline())
        finally:
            child.kill()
            child.communicate(timeout=5)
        crash_id = first["session_id"]
        identities = [json.loads(body)["device"] for (body,) in inspect_queue(qdir, "SELECT opening FROM session")]
        assert len(identities) == 2 and all(d == identities[0] for d in identities)
        assert identities[0]["id"] and identities[0]["method"] in {"windows_installation_v1", "local_profile_v1"}
        summary["stable_device_across_processes"] = True
        api_env = dict(os.environ, VIPNET_DATABASE_URL=config["api_url"], VIPNET_TRUSTED_PROXIES="")

        def live():
            return serve(api_port, cert, key, api_env, evidence / "api.log")

        edge_port = port()
        tests["TEST_EDGE"] = f"https://127.0.0.1:{edge_port}"
        with live(), serve(edge_port, cert, key, dict(api_env, VIPNET_TRUSTED_PROXIES="127.0.0.1/32"), evidence / "edge.log"):
            result = run([sys.executable, "-m", "unittest", "server.test_api", "-v"], tests)
            (evidence / "api-tests.txt").write_bytes(result.stderr)
            summary["integration_tests"] = result.stderr.decode().strip().splitlines()[-1]
            time.sleep(3)
            attempt = subprocess.run([exe, "--sync"], env=env, capture_output=True, timeout=30)
            assert attempt.returncode == 3, attempt.stderr
            errors = inspect_queue(qdir, "SELECT last_error FROM session")
            assert all(code == -12175 for (code,) in errors), errors
            summary["untrusted_tls"] = "rejected; retained"
        with ExitStack() as positive:
            if disposable:
                positive.enter_context(runner_trust(der, thumbprint))
                positive.enter_context(live())
                uploader = exe
                summary["positive_transport"] = "release WinHTTP over direct trusted TLS"
            else:
                backend_port = port()
                positive.enter_context(serve(backend_port, cert, key, api_env, evidence / "api.log"))
                positive.enter_context(loopback_relay(api_port, backend_port, cert))
                uploader = exe.with_name("vipnet-loopback-fixture.exe")
                summary["positive_transport"] = (
                    "native WinHTTP fixture to loopback relay, verified TLS to API"
                )
            due = max(row[0] for row in inspect_queue(qdir, "SELECT due FROM session"))
            time.sleep(max(0, due - time.time() + 0.2))
            replay = private / "replay"
            replay.mkdir()
            with (
                closing(sqlite3.connect(qdir / "queue.sqlite3")) as original,
                closing(sqlite3.connect(replay / "queue.sqlite3")) as copy,
            ):
                original.backup(copy)
            attempt = subprocess.run([uploader, "--sync"], env=env, capture_output=True, timeout=40)
            assert attempt.returncode == 0, (
                attempt.returncode,
                attempt.stderr,
                inspect_queue(qdir, "SELECT last_error FROM session"),
            )
            assert not inspect_queue(qdir, "SELECT id FROM session")
            # Reopen the pre-acknowledgement snapshot after the server has committed both manifests.
            run([uploader, "--sync"], dict(env, VIPNET_QUEUE_DIR=str(replay)))
            assert not inspect_queue(replay, "SELECT id FROM session")
            summary["replay_of_closed_sessions"] = 2
            with psycopg.connect(config["owner"]) as db:

                def saved(s):
                    return db.execute(
                        "SELECT payload FROM mtr.sample WHERE session_id=%s ORDER BY sequence,row_no", (s,)
                    ).fetchall()

                assert [r[0] for r in saved(sid)] == rows
                assert saved(crash_id)[0][0] == first
                for s, expected in ((sid, "completed"), (crash_id, "partial")):
                    assert db.execute("SELECT state FROM core.session WHERE id=%s", (s,)).fetchone() == (
                        expected,
                    )
                summary["crash_samples"] = len(saved(crash_id))
        worker_env = dict(os.environ, VIPNET_DATABASE_URL=config["worker_url"])
        with psycopg.connect(config["owner"]) as db:
            count = db.execute("SELECT count(*) FROM diagnostics.job WHERE state='pending'").fetchone()[0]
        for _ in range(count):
            run([sys.executable, "-m", "server.worker", "--once"], worker_env)
        dump = evidence / "internet_diagnostics.dump"
        db_env = dict(os.environ, **config["pg_env"])
        run([pg / "pg_dump", "-Fc", "-f", dump, "internet_diagnostics"], db_env)
        run([pg / "pg_restore", "--exit-on-error", "--single-transaction", "-d", "restored", dump], db_env)

        def snapshot(dsn):
            with psycopg.connect(dsn) as db:
                return {
                    table: db.execute(
                        f"SELECT count(*),md5(coalesce(string_agg(to_jsonb(t)::text,'|' "
                        f"ORDER BY to_jsonb(t)::text),'')) FROM {table} t"
                    ).fetchone()
                    for table in (
                        "core.session",
                        "core.chunk",
                        "core.run_origin",
                        "mtr.sample",
                        "mtr.sample_key",
                        "diagnostics.job",
                        "diagnostics.analysis",
                        "security.principal",
                        "security.audit",
                    )
                }

        before = snapshot(config["owner"])
        assert snapshot(config["restored"]) == before
        with psycopg.connect(config["restored"]) as db:
            assert db.execute("SELECT version_num FROM alembic_version").fetchone() == ("v051",)
            assert (
                db.execute("""SELECT has_table_privilege('netdiag_api','core.chunk','INSERT'),
                                  has_table_privilege('netdiag_api','security.audit','DELETE'),
                                  has_table_privilege('netdiag_worker','diagnostics.analysis','INSERT')""").fetchone()
                == (True, False, True)
            )
            assert db.execute("SELECT count(*) FROM diagnostics.job WHERE state<>'done'").fetchone() == (0,)
        restored_port = port()
        restored_env = dict(api_env, VIPNET_DATABASE_URL=config["api_url"].rsplit("/", 1)[0] + "/restored")
        with serve(restored_port, cert, key, restored_env, evidence / "api.log"):
            with httpx.Client(verify=ssl.create_default_context(cafile=cert), trust_env=False) as client:
                res = client.get(
                    f"https://127.0.0.1:{restored_port}/api/v1/sessions/{sid}",
                    headers={"Authorization": "Bearer " + token},
                )
                assert res.status_code == 200 and res.json()["state"] == "completed"
        summary["restored_api"] = "authenticated session read passed"
        summary["backup_sha256"] = digest(dump)
        summary["restored_counts"] = {table: n for table, (n, _) in before.items()}
        summary["completed_utc"] = datetime.now(timezone.utc).isoformat()
        (evidence / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pg_bin", type=Path)
    parser.add_argument("exe", type=Path)
    parser.add_argument("new_evidence_directory", type=Path)
    parser.add_argument("--disposable-runner", action="store_true")
    a = parser.parse_args()
    try:
        qualify(
            a.pg_bin.resolve(strict=True),
            a.exe.resolve(strict=True),
            a.new_evidence_directory.resolve(),
            a.disposable_runner,
        )
    except subprocess.CalledProcessError as exc:
        sys.stderr.buffer.write(exc.stdout or b"")
        sys.stderr.buffer.write(exc.stderr or b"")
        raise
