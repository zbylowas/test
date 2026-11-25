"""Durable analysis worker. A crashed claimant's lease can be taken over."""

import argparse
import hashlib
import json
import os
import time
from ipaddress import ip_address
from uuid import UUID

from rules.mtr import VERSION, interpret
from server.database import engine, run


def claim():
    with engine().begin() as conn:
        row = run(
            conn,
            """WITH candidate AS (
                  SELECT session_id FROM diagnostics.job WHERE (state='pending' AND available_at <= now())
                  OR (state='running' AND lease_until <= now()) ORDER BY available_at,session_id
                  FOR UPDATE SKIP LOCKED LIMIT 1)
                  UPDATE diagnostics.job j SET state='running',generation=generation+1,
                  lease_until=now()+make_interval(secs=>:seconds) FROM candidate c
                  WHERE j.session_id=c.session_id RETURNING j.session_id,j.generation""",
            seconds=int(os.getenv("VIPNET_LEASE_SECONDS", "120")),
        ).first()
        return tuple(row) if row else None


def calculate(conn, sid):
    samples = []
    manifest = run(
        conn,
        """SELECT digest,row_count FROM core.chunk WHERE session_id=:sid ORDER BY sequence""",
        sid=sid,
    ).all()
    rows = run(
        conn, """SELECT payload FROM mtr.sample WHERE session_id=:sid ORDER BY sequence,row_no""", sid=sid
    )
    for (sample,) in rows:
        sample["session_id"] = str(sid)
        sample["target"] = str(ip_address(sample["target"]))
        if sample["responder"]:
            sample["responder"] = str(ip_address(sample["responder"]))
        samples.append(sample)
    if len(samples) != sum(n for _, n in manifest):
        raise ValueError("raw_samples_unavailable")
    digest = hashlib.sha256(b"".join(d for d, _ in manifest)).digest()
    return digest, interpret(samples)


def persist(conn, sid, digest, result):
    return (
        run(
            conn,
            """INSERT INTO diagnostics.analysis(session_id,rules_version,input_digest,result)
            VALUES (:sid,:version,:digest,CAST(:result AS jsonb)) ON CONFLICT DO NOTHING RETURNING session_id""",
            sid=sid,
            version=VERSION,
            digest=digest,
            result=json.dumps(result, allow_nan=False),
        ).first()
        is not None
    )


def reanalyze(sid):
    with engine().begin() as conn:
        ready = run(
            conn, """SELECT state FROM diagnostics.job WHERE session_id=:sid FOR SHARE""", sid=sid
        ).scalar()
        if ready != "done":
            raise ValueError("session has no completed analysis job")
        digest, result = calculate(conn, sid)
        return persist(conn, sid, digest, result)


def process(job):
    sid, generation = job
    try:
        with engine().connect() as reader:
            digest, result = calculate(reader, sid)
        with engine().begin() as conn:
            won = run(
                conn,
                """UPDATE diagnostics.job SET state='done',lease_until=NULL,error=NULL
                      WHERE session_id=:sid AND generation=:gen AND state='running' AND lease_until>now()
                      RETURNING session_id""",
                sid=sid,
                gen=generation,
            ).first()
            if won:
                persist(conn, sid, digest, result)
        return bool(won)
    except Exception as exc:
        with engine().begin() as conn:
            run(
                conn,
                """UPDATE diagnostics.job SET state=CASE WHEN generation>=5 THEN 'failed' ELSE 'pending' END,
                     lease_until=NULL,available_at=now()+interval '10 seconds',error=:error
                     WHERE session_id=:sid AND generation=:gen AND state='running'""",
                sid=sid,
                gen=generation,
                error=type(exc).__name__,
            )
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--reanalyze", type=UUID, metavar="CLOSED_SESSION")
    args = parser.parse_args()
    if args.reanalyze:
        print("created" if reanalyze(args.reanalyze) else "unchanged")
        raise SystemExit(0)
    while True:
        job = claim()
        if job:
            process(job)
        if args.once:
            break
        if not job:
            time.sleep(1)
