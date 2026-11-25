import os
from functools import lru_cache

from sqlalchemy import create_engine, text


@lru_cache
def engine():
    url = os.environ["VIPNET_DATABASE_URL"]
    if not url.startswith("postgresql+psycopg://"):
        raise ValueError("VIPNET_DATABASE_URL requires postgresql+psycopg")
    return create_engine(
        url,
        pool_pre_ping=True,
        hide_parameters=True,
        connect_args={"connect_timeout": 5, "options": "-c timezone=UTC"},
    )


def run(conn, sql, **params):
    return conn.execute(text(sql), params)


def audit(conn, actor, sid, event):
    run(
        conn,
        "INSERT INTO security.audit(actor, session_id, event) VALUES (:actor,:sid,:event)",
        actor=actor,
        sid=sid,
        event=event,
    )
