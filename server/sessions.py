import json
import os
from ipaddress import ip_address
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from server.access import Problem
from server.database import audit, engine, run
from server.wire import decode
from rules.throughput import confirmed_bytes


def conflict(detail):
    raise Problem(409, "conflict", detail)


def visibility(actor):
    if actor.role == "operator":
        return "owner_id IN (SELECT id FROM security.principal WHERE tenant=:scope)", actor.tenant
    return "owner_id=:scope", actor.id


def status(conn, sid, actor, lock=False):
    clause, scope = visibility(actor)
    suffix = " FOR UPDATE" if lock else ""
    row = (
        run(
            conn,
            f"""SELECT id,state,open_digest,finish_digest,total_bytes,client_version,started_at,measurement,
                  inventory IS NOT NULL AS has_inventory, throughput IS NOT NULL AS has_throughput FROM core.session WHERE id=:sid AND {clause}{suffix}""",
            sid=sid,
            scope=scope,
        )
        .mappings()
        .first()
    )
    if not row:
        raise Problem(404, "not_found", "Brak sesji.")
    return row


def state(sid, value):
    return {"session_id": str(sid), "state": value}


def write_lock(conn):
    # Serializes capacity reservations and open/close within this dedicated database.
    run(conn, "SELECT pg_advisory_xact_lock(7401001)")


def ingest(kind, sid, seq, raw, actor):
    if actor.role != "client":
        raise Problem(403, "scope", "Token nie ma prawa zapisu sesji.")
    doc, digest = decode(raw, kind)
    if kind == "session" and UUID(doc["session_id"]) != sid:
        raise Problem(422, "session_id", "Niezgodny identyfikator sesji.")
    if kind == "session" and "throughput" in doc:
        transfer = doc["throughput"]
        if UUID(transfer["session_id"]) != sid:
            raise Problem(422, "session_id", "Niezgodny identyfikator pomiaru transferu.")
        for sample in (r for phase in transfer["phases"].values() for r in phase):
            if (sample["ms"] is None) == (sample["error"] is None):
                raise Problem(422, "probe", "Próbka wymaga czasu lub przyczyny braku wyniku.")
        for item in transfer["transfers"].values():
            if item["status"] == "ok" and (
                not confirmed_bytes(transfer["profile"], item["client_bytes"], item["node_bytes"]) or not item["duration_ms"]
                or item["reason"] is not None or item["node_duration_ms"] is None
                or item["started_at"] is None or item["ended_at"] is None
            ):
                raise Problem(422, "byte_count", "Niespójne potwierdzenie transferu.")
    with engine().begin() as conn:
        write_lock(conn)
        if kind == "session":
            if not run(conn, "SELECT 1 FROM core.session WHERE id=:sid", sid=sid).first():
                count = run(conn, "SELECT count(*) FROM core.session WHERE state='open'").scalar_one()
                if count >= int(os.getenv("VIPNET_MAX_OPEN", "1000")):
                    raise Problem(429, "capacity", "Limit aktywnych sesji.", 60)
                run(
                    conn,
                    """INSERT INTO core.session(id,owner_id,started_at,client_version,mode,source_ip,
                            open_digest,measurement,inventory,throughput,device_id,device_method,device_reason,measured_ip)
                       VALUES (:sid,:owner,:start,:version,:mode,:source,:digest,CAST(:settings AS jsonb),
                            CAST(:inventory AS jsonb),CAST(:throughput AS jsonb),:device,:method,:reason,
                            (SELECT address FROM core.run_origin WHERE session_id=:sid AND owner_id=:owner))""",
                    sid=sid,
                    owner=actor.id,
                    start=doc["started_at"],
                    version=doc["client_version"],
                    mode=doc["mode"],
                    throughput=json.dumps(doc["throughput"]) if "throughput" in doc else None,
                    inventory=json.dumps(doc["inventory"]) if "inventory" in doc else None,
                    settings=json.dumps(doc["measurement"]) if "measurement" in doc else None,
                    source=actor.source,
                    device=doc.get("device", {}).get("id"),
                    method=doc.get("device", {}).get("method"),
                    reason=doc.get("device", {}).get("reason"),
                    digest=digest,
                )
                audit(conn, actor.id, sid, "session.open")
                return 201, state(sid, "open")
        row = status(conn, sid, actor, lock=True)
        if kind == "session":
            if row["open_digest"] != digest:
                conflict("Inne dane otwarcia.")
            return 200, state(sid, row["state"])
        if kind == "completion":
            if row["state"] != "open":
                if row["finish_digest"] == digest:
                    return 200, state(sid, row["state"])
                conflict("Sesja już zamknięta z innym manifestem.")
            count, last = run(
                conn, "SELECT count(*),max(sequence) FROM core.chunk WHERE session_id=:sid", sid=sid
            ).one()
            if count != doc["chunk_count"] or (count and last != count - 1):
                conflict("Brak zgodności z manifestem porcji.")
            run(
                conn,
                """UPDATE core.session SET state=:state,ended_at=:ended,finish_digest=:digest,touched_at=now()
                         WHERE id=:sid""",
                sid=sid,
                state=doc["state"],
                ended=doc["ended_at"],
                digest=digest,
            )
            if doc["chunk_count"] or row["measurement"] is not None or not (row["has_inventory"] or row["has_throughput"]):
                run(conn, "INSERT INTO diagnostics.job(session_id) VALUES (:sid)", sid=sid)
            audit(conn, actor.id, sid, "session." + doc["state"])
            return 202, state(sid, doc["state"])
        store_chunk(conn, row, seq, doc["samples"], digest, len(raw), actor)
        return 204, None


def store_chunk(conn, session, seq, samples, digest, size, actor):
    sid = session["id"]
    old = run(
        conn, "SELECT digest FROM core.chunk WHERE session_id=:sid AND sequence=:seq", sid=sid, seq=seq
    ).scalar()
    if old is not None:
        if old != digest:
            conflict("Inna treść pod tym samym numerem.")
        return
    if session["state"] != "open":
        conflict("Sesja zamknięta.")
    if session["total_bytes"] + size > int(os.getenv("VIPNET_SESSION_BYTES", str(16 << 20))):
        raise Problem(413, "session_size", "Limit bajtów sesji.")
    reserved = run(
        conn, "SELECT coalesce(sum(total_bytes),0) FROM core.session WHERE state='open'"
    ).scalar_one()
    if reserved + size > int(os.getenv("VIPNET_OPEN_BYTES", str(256 << 20))):
        raise Problem(429, "capacity", "Limit bajtów otwartych sesji.", 60)
    day = run(conn, "SELECT (now() AT TIME ZONE 'UTC')::date").scalar_one()
    keys, rows = [], []
    for index, sample in enumerate(samples):
        if UUID(sample["session_id"]) != sid or "%" in sample["target"] or "%" in (sample["responder"] or ""):
            raise Problem(422, "sample", "Niezgodna sesja lub zakres adresu.")
        keys.append(
            dict(
                sid=sid,
                target=str(ip_address(sample["target"])),
                proto=sample["protocol"],
                phase=sample["phase"],
                ttl=int(sample["ttl"]),
                attempt=int(sample["attempt"]),
                day=day,
            )
        )
        rows.append(dict(sid=sid, seq=seq, n=index, day=day, payload=json.dumps(sample, allow_nan=False)))
    run(
        conn,
        """INSERT INTO core.chunk(session_id,sequence,digest,row_count)
              VALUES (:sid,:seq,:digest,:n)""",
        sid=sid,
        seq=seq,
        digest=digest,
        n=len(rows),
    )
    try:
        conn.execute(
            text("""INSERT INTO mtr.sample_key(session_id,target,protocol,phase,ttl,attempt,received_day)
                     VALUES (:sid,:target,:proto,:phase,:ttl,:attempt,:day)"""),
            keys,
        )
    except IntegrityError as exc:
        if getattr(exc.orig, "sqlstate", None) == "23505":
            conflict("Powtórzona próbka.")
        raise
    conn.execute(
        text("""INSERT INTO mtr.sample(received_day,session_id,sequence,row_no,payload)
                 VALUES (:day,:sid,:seq,:n,CAST(:payload AS jsonb))"""),
        rows,
    )
    run(
        conn,
        "UPDATE core.session SET total_bytes=total_bytes+:size,touched_at=now() WHERE id=:sid",
        sid=sid,
        size=size,
    )
    audit(conn, actor.id, sid, "chunk.accept")
