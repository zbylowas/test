"""Qualify the release EXE against a system-trusted TLS listener on IPv4 loopback."""

import argparse
import json
import os
import platform
import socket
import sqlite3
import ssl
import sys
import tempfile
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import httpx
import psycopg
from accept_v010 import ROOT, cluster, digest, inspect_queue, port, run, serve
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from phase_loopback import capture


def qualify(pg, exe, evidence, hostname, cert, key, phases=False, inventory=False, legacy_exe=None):
    # This runner uses an isolated database and an issuer-provided development
    # certificate or a staging certificate supplied by the operator.
    def check_loopback():
        addresses = {row[4][0] for row in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)}
        if addresses != {"127.0.0.1"}:
            raise ValueError("The staging hostname must resolve exclusively to 127.0.0.1")

    check_loopback()
    evidence.mkdir(parents=True, exist_ok=False)
    t0 = datetime.now(UTC).isoformat()
    with tempfile.TemporaryDirectory(prefix="vipnet-direct-") as tmp:
        private = Path(tmp)
        with cluster(pg, private) as config:
            owner_env = dict(os.environ, VIPNET_DATABASE_URL=config["owner_url"])
            run(
                [
                    sys.executable,
                    "-m",
                    "alembic",
                    "-c",
                    "server/alembic.ini",
                    "upgrade",
                    "head",
                ],
                owner_env,
            )
            with psycopg.connect(config["owner"]) as db:
                db.execute((ROOT / "server/grants.sql").read_text())
            tenant = str(uuid4())
            token = run(
                [sys.executable, "-m", "server", "issue-token", tenant, "client"],
                owner_env,
            )
            tcp_port = port()
            origin = f"https://{hostname}:{tcp_port}"
            qdir = private / "queue"
            env = dict(os.environ, VIPNET_QUEUE_DIR=str(qdir))
            env.pop("VIPNET_TOKEN", None)
            env.pop("VIPNET_API_ORIGIN", None)
            extra = {}
            if phases:
                extra = capture(exe, env, evidence)
            else:
                rows = run([exe, "5", "2", "400", "127.0.0.1", "::1"], env).stdout
                (evidence / "loopback.ndjson").write_bytes(rows)
            samples = [json.loads(line) for line in (evidence / "loopback.ndjson").read_bytes().splitlines()]
            sid = samples[0]["session_id"]
            if not phases:
                assert len(samples) == 10 and all(s["status"] == "echo_reply" for s in samples)
            assert len(inspect_queue(qdir, "SELECT id FROM session")) == 1
            replay = private / "replay"
            replay.mkdir()
            with (
                closing(sqlite3.connect(qdir / "queue.sqlite3")) as source,
                closing(sqlite3.connect(replay / "queue.sqlite3")) as copy,
            ):
                source.backup(copy)
            api_env = dict(
                os.environ,
                VIPNET_DATABASE_URL=config["api_url"],
                VIPNET_TRUSTED_PROXIES="",
            )
            with serve(
                tcp_port,
                cert,
                key,
                api_env,
                evidence / "api.log",
                hostname=hostname,
                system_trust=True,
            ):
                check_loopback()
                with (
                    socket.create_connection(("127.0.0.1", tcp_port)) as conn,
                    ssl.create_default_context().wrap_socket(conn, server_hostname=hostname) as tls,
                ):
                    leaf = x509.load_der_x509_certificate(tls.getpeercert(binary_form=True))
                    tls_version = tls.version()
                assert leaf == x509.load_pem_x509_certificate(cert.read_bytes())
                env.update(VIPNET_API_ORIGIN=origin, VIPNET_TOKEN=token.stdout.decode().strip())
                for directory in (qdir, replay):
                    run([exe, "--sync"], dict(env, VIPNET_QUEUE_DIR=str(directory)))
                    assert not inspect_queue(directory, "SELECT id FROM session")
                with psycopg.connect(config["owner"]) as db:
                    stored = db.execute(
                        "SELECT payload FROM mtr.sample WHERE session_id=%s ORDER BY sequence,row_no",
                        (sid,),
                    ).fetchall()
                    assert [row[0] for row in stored] == samples
                    assert db.execute("SELECT state FROM core.session WHERE id=%s", (sid,)).fetchone() == (
                        "completed",
                    )
                    assert db.execute("SELECT count(*) FROM core.session").fetchone() == (1,)
                if phases:
                    run(
                        [sys.executable, "-m", "server.worker", "--once"],
                        dict(os.environ, VIPNET_DATABASE_URL=config["worker_url"]),
                    )
                    with psycopg.connect(config["owner"]) as db:
                        version, result = db.execute(
                            "SELECT rules_version,result FROM diagnostics.analysis WHERE session_id=%s",
                            (sid,),
                        ).fetchone()
                        assert (
                            result["sample_count"] == 80
                            and len(result["series"]) == 16
                            and version == "0.2.0"
                        )
                        assert all(item["stats"]["1"]["rcv"] == 5 for item in result["series"])
                        extra.update(rules_version=version, worker_series=len(result["series"]))
                with httpx.Client(verify=ssl.create_default_context(), trust_env=False) as client:
                    assert client.get(origin + "/api/v1/health").status_code == 200
                    if phases:
                        response = client.get(
                            origin + f"/api/v1/sessions/{sid}/analysis",
                            headers={"Authorization": "Bearer " + env["VIPNET_TOKEN"]},
                        )
                        response.raise_for_status()
                        assert response.json()["result"] == result
                        params = response.json()["measurement"]
                        assert params == {
                            "windows_version": platform.version(),
                            "interval_ms": 100,
                            "attempts": 5,
                            "max_ttl": 2,
                            "timeout_ms": 400,
                            "targets": ["127.0.0.1", "::1"],
                            "protocol": "both",
                            "phase_control": True,
                        }
                        assert (
                            response.json()["client_version"]
                            == run([exe, "--version"]).stdout.decode().strip()
                        )
                        extra["persisted_parameters"] = params
                        extra["analysis_read_https"] = True
                    if inventory:
                        from verify_inventory import capture as capture_inventory

                        inventory_queue = private / "inventory-queue"
                        opened = capture_inventory(exe, inventory_queue)
                        inv_id = opened["session_id"]
                        (evidence / "inventory-private.json").write_text(json.dumps(opened), encoding="utf-8")
                        run([exe, "--sync"], dict(env, VIPNET_QUEUE_DIR=str(inventory_queue)))
                        assert not inspect_queue(inventory_queue, "SELECT id FROM session")
                        headers = {"Authorization": "Bearer " + env["VIPNET_TOKEN"]}
                        res = client.get(origin + f"/api/v1/sessions/{inv_id}/inventory", headers=headers)
                        res.raise_for_status()
                        assert res.json() == opened["inventory"]
                        assert (
                            client.get(
                                origin + f"/api/v1/sessions/{sid}/inventory", headers=headers
                            ).status_code
                            == 404
                        )
                        # The same snapshot is also supported alongside a normal MTR session.
                        mixed = run(
                            [exe, "1", "1", "400", "127.0.0.1", "--inventory"],
                            dict(env, VIPNET_QUEUE_DIR=str(inventory_queue)),
                        )
                        mixed_id = json.loads(mixed.stdout)["session_id"]
                        with psycopg.connect(config["owner"]) as db:
                            assert db.execute(
                                "SELECT inventory,state FROM core.session WHERE id=%s", (inv_id,)
                            ).fetchone() == (opened["inventory"], "completed")
                            assert db.execute(
                                "SELECT count(*) FROM diagnostics.job WHERE session_id=%s", (inv_id,)
                            ).fetchone() == (0,)
                            assert db.execute(
                                "SELECT inventory IS NOT NULL,measurement IS NOT NULL,state "
                                "FROM core.session WHERE id=%s",
                                (mixed_id,),
                            ).fetchone() == (True, True, "completed")
                        extra["inventory_offline_https_postgres_equal"] = True
                        extra["combined_mtr_inventory_completed"] = True
                        extra["inventory_sha256"] = digest(evidence / "inventory-private.json")
                    if legacy_exe:
                        oldqueue = private / "previous-client"
                        local = dict(os.environ, VIPNET_QUEUE_DIR=str(oldqueue))
                        local.pop("VIPNET_API_ORIGIN", None)
                        local.pop("VIPNET_TOKEN", None)
                        rows = run([legacy_exe, "1", "1", "400", "127.0.0.1"], local).stdout
                        old_id = json.loads(rows)["session_id"]
                        run([exe, "--sync"], dict(env, VIPNET_QUEUE_DIR=str(oldqueue)))
                        assert not inspect_queue(oldqueue, "SELECT id FROM session")
                        with psycopg.connect(config["owner"]) as db:
                            assert db.execute(
                                "SELECT state,client_version,inventory FROM core.session WHERE id=%s",
                                (old_id,),
                            ).fetchone() == ("completed", "0.2.0", None)
                        extra["real_v020_offline_queue_uploaded"] = True
    summary = dict(
        start_utc=t0,
        completed_utc=datetime.now(UTC).isoformat(),
        windows=platform.platform(),
        version=run([exe, "--version"]).stdout.decode().strip(),
        exe_sha256=digest(exe),
        postgres=run([pg / "postgres", "--version"]).stdout.decode().strip(),
        targets=["127.0.0.1", "::1"],
        rounds=5,
        max_ttl=2,
        timeout_ms=400,
        origin=origin,
        listener="127.0.0.1",
        transport="release WinHTTP direct HTTPS",
        preflight_tls=tls_version,
        issuer=leaf.issuer.rfc4514_string(),
        leaf_sha256=leaf.fingerprint(hashes.SHA256()).hex(),
        measurements_sha256=digest(evidence / "loopback.ndjson"),
        samples_equal=len(samples),
        acknowledged_queues=2,
        sessions_after_replay=1,
        state="completed",
        **extra,
    )
    (evidence / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("pg", "exe", "evidence", "cert", "key"):
        parser.add_argument("--" + option, required=True, type=lambda p: Path(p).resolve())
    parser.add_argument("--hostname", required=True)
    parser.add_argument("--phases", action="store_true")
    parser.add_argument("--inventory", action="store_true")
    parser.add_argument("--legacy-exe", type=lambda p: Path(p).resolve(strict=True))
    qualify(**vars(parser.parse_args()))
