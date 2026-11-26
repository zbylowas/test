"""Web panels, the public Windows download and client-scoped measurement reservations."""
import hashlib
import hmac
import json
import os
import secrets
from importlib import import_module
from pathlib import Path
from typing import Annotated, Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import IPvAnyAddress
from starlette.concurrency import run_in_threadpool

from server.access import Actor, Problem, admit, authenticate, source_address
from server.database import engine, run
from server.sessions import visibility
from server.wire import VALIDATORS

router = APIRouter(prefix="/api/v1/portal")
Auth = Annotated[Actor, Depends(authenticate)]
node = import_module("measurement-node.transfer")


@router.post("/clients", status_code=201)
def enroll(request: Request):
    source = source_address(request)
    admit(source)
    key = os.getenv("VIPNET_ENROLL_KEY", "")
    if len(key) < 32:
        raise Problem(503, "registration_disabled", "Rejestracja klientów jest wyłączona.")
    token = secrets.token_urlsafe(32)
    with engine().begin() as conn:
        accepted = run(conn, "SELECT security.enroll_client(:id,:digest,:peer)", id=uuid4(),
                       digest=hashlib.sha256(token.encode()).digest(),
                       peer=hmac.digest(key.encode(), source.encode(), "sha256")).scalar_one()
    if not accepted:
        raise Problem(429, "enrollment_limit", "Dzienny limit rejestracji został osiągnięty.")
    return JSONResponse({"token": token}, status_code=201, headers={"Cache-Control": "no-store"})


@router.get("/game-profiles")
def game_profiles():
    path = Path(os.getenv("VIPNET_GAME_PROFILES") or Path(__file__).with_name("game-profiles.json"))
    with path.open("rb") as stream:
        data = stream.read(32769)
    if len(data) > 32768:
        raise Problem(503, "catalog_size", "Katalog gier przekracza limit.")
    try:
        catalog = json.loads(data)
    except ValueError:
        raise Problem(503, "invalid_catalog", "Katalog gier ma niepoprawny format.")
    if not VALIDATORS["game-profiles"].is_valid(catalog):
        raise Problem(503, "invalid_catalog", "Sprawdź profile i adresy w katalogu gier.")
    return catalog


@router.get("/me")
def identity(actor: Auth):
    return {"role": actor.role}


@router.post("/runs/{sid}", status_code=201)
async def reserve(sid: UUID, actor: Auth, profile: Literal["legacy", "capacity"] = "legacy"):
    if actor.role != "client":
        raise Problem(403, "scope", "Pomiar wymaga konta klienta.")
    offer = node.start_run(sid, capacity=profile == "capacity")
    reservation = node.active
    try:
        await run_in_threadpool(record_origin, sid, actor)
    except BaseException:
        if node.active is reservation:
            node.active = None
        raise
    return {**offer, "observed_ip": actor.source, "accepts_desktop_trace": True}


def record_origin(sid, actor):
    with engine().begin() as conn:
        recorded = run(conn, """INSERT INTO core.run_origin(session_id,owner_id,address)
            VALUES(:sid,:owner,:ip) ON CONFLICT DO NOTHING RETURNING session_id""",
            sid=sid, owner=actor.id, ip=actor.source).scalar()
        if recorded is None:
            raise Problem(409, "run_reused", "Ta sesja miała już rezerwację pomiaru.")


@router.get("/sessions")
def sessions(actor: Auth, state: Literal["completed", "partial", "open", "failed", "cancelled"] | None = None,
             ip: IPvAnyAddress | None = None, device_id: UUID | None = None, client_id: UUID | None = None,
             limit: Annotated[int, Query(ge=1, le=50)] = 20,
             offset: Annotated[int, Query(ge=0, le=1000000)] = 0):
    clause, scope = visibility(actor)
    if state:
        clause += " AND state=:state"
    if ip is not None:
        clause += " AND coalesce(measured_ip,source_ip)=CAST(:ip AS inet)"
    if device_id is not None:
        clause += " AND device_id=:device"
    if client_id is not None:
        clause += " AND owner_id=:client"
    with engine().connect() as conn:
        rows = run(conn, f"""SELECT id AS session_id,state,started_at,client_version,measurement,owner_id AS client_id,
            device_id,device_method,device_reason,host(coalesce(measured_ip,source_ip)) AS ip,
            host(source_ip) AS sync_ip, CASE WHEN measured_ip IS NULL THEN 'sync' ELSE 'reservation' END AS ip_source
            FROM core.session
            WHERE {clause} ORDER BY started_at DESC,id LIMIT :limit OFFSET :offset""",
                   scope=scope, state=state, limit=limit+1, offset=offset, ip=str(ip) if ip else None,
                   device=device_id, client=client_id).mappings().all()
    return {"items": rows[:limit], "has_more": len(rows) > limit}


def install_web(app):
    root = Path(os.getenv("VIPNET_WEB_DIR", Path(__file__).resolve().parents[1] / "frontend/dist"))
    app.include_router(router)
    app.include_router(node.app.router)
    app.mount("/assets", StaticFiles(directory=root / "assets", check_dir=False), name="assets")

    @app.get("/")
    @app.get("/klient")
    @app.get("/admin")
    def index():
        if not (root / "index.html").is_file():
            raise Problem(503, "portal_missing", "Panel oczekuje na instalację.")
        return FileResponse(root / "index.html", headers={
            "Cache-Control": "no-cache", "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; "
                                       "connect-src 'self'; img-src 'self' data:; object-src 'none'; "
                                       "frame-ancestors 'none'; base-uri 'none'; form-action 'self'"})

    @app.get("/pobierz/windows-release.json")
    def windows_release():
        path = root / "windows-release.json"
        if not path.is_file():
            raise Problem(503, "download_missing", "Metadane wydania są niedostępne.")
        return FileResponse(path, media_type="application/json", headers={"Cache-Control":"no-cache"})

    @app.get("/pobierz/VIP-NET-Diagnostyka-Setup.msi")
    def download_installer():
        setup = root / "VIP-NET-Diagnostyka-Setup.msi"
        if not setup.is_file():
            raise Problem(503, "download_missing", "Instalator oczekuje na publikację.")
        return FileResponse(setup, filename=setup.name, media_type="application/x-msi",
                            headers={"X-Content-Type-Options": "nosniff", "Cache-Control": "no-cache"})

    @app.get("/pobierz/VIP-NET-Diagnostyka.exe.sha256")
    def checksum():
        exe = root / "VIP-NET-Diagnostyka.exe"
        if not exe.is_file():
            raise Problem(503, "download_missing", "Aplikacja oczekuje na publikację.")
        with exe.open("rb") as binary:
            digest = hashlib.file_digest(binary, "sha256").hexdigest()
        return PlainTextResponse(f"{digest}  {exe.name}\n", headers={"Cache-Control":"no-cache"})

    @app.get("/pobierz/VIP-NET-Diagnostyka.exe")
    def download():
        exe = root / "VIP-NET-Diagnostyka.exe"
        if not exe.is_file():
            raise Problem(503, "download_missing", "Aplikacja oczekuje na publikację.")
        return FileResponse(exe, filename=exe.name, media_type="application/octet-stream",
                            headers={"X-Content-Type-Options": "nosniff", "Cache-Control": "no-cache"})
