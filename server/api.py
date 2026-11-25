from typing import Annotated
from uuid import UUID

from fastapi import Depends, FastAPI, Path, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from sqlalchemy.exc import DataError, OperationalError, SQLAlchemyError
from starlette.concurrency import run_in_threadpool

from rules.throughput import interpret as interpret_throughput
from rules.mtr import VERSION as RULES_VERSION
from server.access import Actor, Problem, authenticate
from server.database import engine, run
from server.sessions import ingest, state, status, visibility
from server.wire import DOCUMENTS, read_body
from server.portal import install_web

app = FastAPI(title="VIP-NET Internet Diagnostics", version="0.7.4", openapi_url=None)
install_web(app)
Auth = Annotated[Actor, Depends(authenticate)]
BASE = "/api/v1"


@app.exception_handler(Problem)
async def problem(request, exc):
    headers = {"Retry-After": str(exc.retry)} if exc.retry else {}
    return JSONResponse({"code": exc.code, "detail": exc.detail}, status_code=exc.status, headers=headers)


@app.exception_handler(RequestValidationError)
async def parameter_error(request, exc):
    return await problem(request, Problem(422, "validation", "Niepoprawne parametry."))


@app.exception_handler(OperationalError)
async def database_error(request, exc):
    return await problem(request, Problem(503, "storage", "Baza czasowo niedostępna.", 5))


@app.exception_handler(DataError)
async def invalid_storage_value(request, exc):
    return await problem(request, Problem(422, "validation", "Wartość poza zakresem magazynu."))


@app.get(BASE + "/health")
def health():
    try:
        with engine().connect() as conn:
            ready = run(
                conn,
                """SELECT version_num='v051' AND to_regclass('mtr.p' ||
                    to_char(now() AT TIME ZONE 'UTC','YYYYMMDD')) IS NOT NULL FROM alembic_version""",
            ).scalar()
    except SQLAlchemyError:
        ready = False
    if not ready:
        raise Problem(503, "storage", "Brak migracji lub dzisiejszej partycji.")
    return {"version": "0.7.4", "status": "ready"}


@app.get(BASE + "/sessions")
def history(
    actor: Auth,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0, le=1000000)] = 0,
):
    clause, scope = visibility(actor)
    with engine().connect() as conn:
        rows = run(
            conn,
            f"""SELECT id,state FROM core.session WHERE {clause}
                   ORDER BY received_at DESC,id LIMIT :limit OFFSET :offset""",
            scope=scope,
            limit=limit,
            offset=offset,
        )
        return [state(sid, value) for sid, value in rows]


@app.get(BASE + "/sessions/{session_id}")
def get_session(session_id: UUID, actor: Auth):
    with engine().connect() as conn:
        return state(session_id, status(conn, session_id, actor)["state"])


@app.get(BASE + "/sessions/{session_id}/inventory")
def get_inventory(session_id: UUID, actor: Auth):
    clause, scope = visibility(actor)
    with engine().connect() as conn:
        doc = run(
            conn,
            f"SELECT inventory FROM core.session WHERE id=:sid AND {clause}",
            sid=session_id,
            scope=scope,
        ).scalar()
    if doc is None:
        raise Problem(404, "inventory_not_found", "Brak dostępnego pomiaru komputera i sieci.")
    return doc


@app.get(BASE + "/sessions/{session_id}/throughput")
def get_throughput(session_id: UUID, actor: Auth):
    clause, scope = visibility(actor)
    with engine().connect() as conn:
        doc = run(conn, f"SELECT throughput FROM core.session WHERE id=:sid AND {clause}",
                  sid=session_id, scope=scope).scalar()
    if doc is None:
        raise Problem(404, "throughput_not_found", "Brak pomiaru przepustowości.")
    return {"session_id": str(session_id), "throughput": doc, "interpretation": interpret_throughput(doc)}


@app.get(BASE + "/sessions/{session_id}/mtr")
def mtr_samples(session_id: UUID, actor: Auth, offset: Annotated[int, Query(ge=0, le=1000000)] = 0,
                limit: Annotated[int, Query(ge=1, le=128)] = 64):
    with engine().connect() as conn:
        status(conn, session_id, actor)
        rows = run(conn, """SELECT payload FROM mtr.sample WHERE session_id=:sid
            ORDER BY sequence,row_no LIMIT :limit OFFSET :offset""",
            sid=session_id, limit=limit+1, offset=offset).scalars().all()
    return {"session_id": str(session_id), "items": rows[:limit], "has_more": len(rows) > limit}


@app.get(BASE + "/sessions/{session_id}/analysis")
def get_analysis(
    session_id: UUID,
    actor: Auth,
    rules_version: Annotated[str, Query(min_length=1, max_length=32)] = RULES_VERSION,
):
    with engine().connect() as conn:
        session = status(conn, session_id, actor)
        row = run(
            conn,
            """SELECT encode(input_digest,'hex'),result FROM diagnostics.analysis
                  WHERE session_id=:sid AND rules_version=:version ORDER BY input_digest LIMIT 1""",
            sid=session_id,
            version=rules_version,
        ).first()
    if not row:
        raise Problem(404, "analysis_not_found", "Brak wyniku dla tej wersji reguł.")
    return {
        "session_id": str(session_id),
        "rules_version": rules_version,
        "client_version": session["client_version"],
        "started_at": session["started_at"],
        "measurement": session["measurement"],
        "input_sha256": row[0],
        "result": row[1],
    }


async def put(request, kind, sid, actor, sequence=None):
    raw = await read_body(request)
    code, data = await run_in_threadpool(ingest, kind, sid, sequence, raw, actor)
    return JSONResponse(data, status_code=code) if data is not None else Response(status_code=code)


@app.put(BASE + "/sessions/{session_id}")
async def open_session(session_id: UUID, request: Request, actor: Auth):
    return await put(request, "session", session_id, actor)


@app.put(BASE + "/sessions/{session_id}/chunks/{sequence}")
async def chunk(
    session_id: UUID, sequence: Annotated[int, Path(ge=0, le=65535)], request: Request, actor: Auth
):
    return await put(request, "chunk", session_id, actor, sequence)


@app.put(BASE + "/sessions/{session_id}/completion")
async def finish(session_id: UUID, request: Request, actor: Auth):
    return await put(request, "completion", session_id, actor)


@app.get(BASE + "/{document}")
def contract(document: str):
    if document not in DOCUMENTS:
        raise Problem(404, "not_found", "Brak dokumentu.")
    return DOCUMENTS[document]
