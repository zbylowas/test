"""Run daily as the dedicated database owner, separately from the API."""

import os
import re
from datetime import date, timedelta

from server.database import audit, engine, run
from server.sessions import write_lock


def positive(name, default):
    value = int(os.getenv(name, default))
    if value < 1:
        raise ValueError(name)
    return value


def maintain():
    raw_days = positive("VIPNET_RAW_DAYS", 90)
    months = positive("VIPNET_ANALYSIS_MONTHS", 24)
    idle = positive("VIPNET_IDLE_HOURS", 168)
    with engine().begin() as conn:
        write_lock(conn)
        run(conn, "DELETE FROM core.run_origin WHERE observed_at < now()-make_interval(days=>:days)",
            days=raw_days)
        today = run(conn, "SELECT (now() AT TIME ZONE 'UTC')::date").scalar_one()
        for day in (today, today + timedelta(days=1), today + timedelta(days=2)):
            end = day + timedelta(days=1)
            run(
                conn,
                f"""CREATE TABLE IF NOT EXISTS mtr.p{day:%Y%m%d} PARTITION OF mtr.sample
                         FOR VALUES FROM ('{day}') TO ('{end}')""",
            )
        names = (
            run(
                conn,
                """SELECT child.relname FROM pg_inherits JOIN pg_class child ON child.oid=inhrelid
                          WHERE inhparent='mtr.sample'::regclass AND child.relnamespace='mtr'::regnamespace""",
            )
            .scalars()
            .all()
        )
        for name in names:
            if re.fullmatch(r"p[0-9]{8}", name) and date.fromisoformat(name[1:]) < today - timedelta(
                days=raw_days
            ):
                run(conn, f"DROP TABLE mtr.{name}")
        run(
            conn,
            """DELETE FROM mtr.sample_key k USING core.session s
                  WHERE k.received_day<:cutoff AND s.id=k.session_id AND s.state<>'open'""",
            cutoff=today - timedelta(days=raw_days),
        )
        run(
            conn,
            "DELETE FROM diagnostics.analysis WHERE created_at<now()-make_interval(months=>:months)",
            months=months,
        )
        run(
            conn,
            """UPDATE core.session SET inventory=NULL, throughput=NULL WHERE (inventory IS NOT NULL OR throughput IS NOT NULL) AND state<>'open'
                  AND received_at < now()-make_interval(days=>:days)""",
            days=raw_days,
        )
        stale = run(
            conn,
            """UPDATE core.session SET state='partial', ended_at=now(), touched_at=now()
                WHERE state='open' AND touched_at<now()-make_interval(hours=>:hours) RETURNING id""",
            hours=idle,
        ).scalars()
        for sid in stale:
            run(conn, "INSERT INTO diagnostics.job(session_id) VALUES (:sid)", sid=sid)
            audit(conn, None, sid, "session.idle_partial")


if __name__ == "__main__":
    maintain()
