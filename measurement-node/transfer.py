"""Single-worker, bounded HTTPS measurement origin. Terminate TLS at the trusted proxy."""

import asyncio
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass, field
from uuid import UUID
from typing import Literal

from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import StreamingResponse

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
BASE = "/measure/v1/runs/{sid}"
BLOCK = 32768
PAYLOAD = os.urandom(BLOCK)
CAPACITY_PAYLOAD = os.urandom(1 << 20)


def setting(name, default, low, high):
    value = int(os.environ.get(name, default))
    if not low <= value <= high:
        raise ValueError(f"invalid {name}")
    return value


def profile():
    size = setting("VIPNET_TRANSFER_BYTES", 8 << 20, 65536, 64 << 20)
    rate = setting("VIPNET_TRANSFER_BPS", 16_000_000, 262144, 100_000_000)
    expiry = setting("VIPNET_TRANSFER_SECONDS", 60, 10, 180)
    # Reserve enough time for two rate-limited transfers plus the quiet phases.
    if size * 16 / rate + 6 >= expiry:
        raise ValueError("profile exceeds the run deadline")
    return {"bytes": size, "rate_bps": rate, "deadline_s": expiry}


@dataclass
class Batch:
    name: str
    started: float = field(default_factory=time.monotonic)
    allocated: int = 0
    completed: int = 0
    pending: int = 0
    indices: set = field(default_factory=set)


@dataclass
class Run:
    sid: UUID
    limits: dict
    ticket: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    started: float = field(default_factory=time.monotonic)
    last_ping: float = 0
    counts: dict = field(default_factory=dict)
    busy: bool = False
    batch: Batch | None = None

    @property
    def deadline(self):
        return self.started + self.limits["deadline_s"]


active: Run | None = None


def authorized(request, token):
    supplied = request.headers.get("authorization", "").encode("latin-1")
    return bool(token) and hmac.compare_digest(supplied, ("Bearer " + token).encode())


def current(sid, request):
    if not active or active.sid != sid or not authorized(request, active.ticket):
        raise HTTPException(403)
    if time.monotonic() >= active.deadline:
        raise HTTPException(410)
    return active


@app.post(BASE, status_code=201)
async def reserve(sid: UUID, request: Request):
    key = os.environ.get("VIPNET_NODE_TOKEN", "")
    if len(key) < 32 or not authorized(request, key):
        raise HTTPException(403)
    return start_run(sid)


def start_run(sid: UUID, capacity=False):
    """Called on the event loop after checking either the node key or the client identity."""
    global active
    if active and time.monotonic() < active.deadline:
        raise HTTPException(429, headers={"Retry-After": "3"})
    limits = profile()
    if capacity and os.getenv("VIPNET_CAPACITY_BPS"):
        limits = {"mode": "windowed", "bytes": 512 << 20, "window_ms": 5000, "streams": 4,
                  "deadline_s": 90, "rate_bps": setting("VIPNET_CAPACITY_BPS", 1000000000, 262144, 1000000000)}
    active = Run(sid, limits)
    return {"session_id": str(sid), "ticket": active.ticket, "profile": active.limits,
            "node_id": os.environ.get("VIPNET_NODE_ID", "staging")}


@app.head(BASE + "/latency")
async def latency(sid: UUID, request: Request):
    job = current(sid, request)
    now = time.monotonic()
    if now - job.last_ping < 0.04:
        raise HTTPException(429)
    job.last_ping = now
    return Response(status_code=204, headers={"Cache-Control": "no-store"})


def begin(job, direction):
    if job.busy or direction in job.counts or job.limits.get("mode") == "windowed":
        raise HTTPException(409)
    job.busy = True
    rec = job.counts[direction] = {"bytes": 0, "duration_ms": 0, "complete": False}
    return rec


async def pace(start, total, job):
    remaining = start + total * 8 / job.limits["rate_bps"] - time.monotonic()
    if remaining > 0:
        await asyncio.sleep(remaining)


def finish(job, rec, start):
    rec["duration_ms"] = (time.monotonic() - start) * 1000
    job.busy = False


@app.get(BASE + "/download")
async def download(sid: UUID, request: Request):
    job = current(sid, request)
    rec = begin(job, "download")

    async def stream():
        start = time.monotonic()
        try:
            async with asyncio.timeout(max(0, job.deadline - start)):
                while rec["bytes"] < job.limits["bytes"]:
                    size = min(BLOCK, job.limits["bytes"] - rec["bytes"])
                    await pace(start, rec["bytes"] + size, job)
                    yield PAYLOAD[:size]
                    rec["bytes"] += size
                rec["complete"] = True
        finally:
            finish(job, rec, start)

    return StreamingResponse(stream(), media_type="application/octet-stream",
                             headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})


@app.post(BASE + "/upload")
async def upload(sid: UUID, request: Request):
    job = current(sid, request)
    if request.headers.get("content-length") != str(job.limits["bytes"]) or request.headers.get("content-encoding"):
        raise HTTPException(413)
    rec = begin(job, "upload")
    start = time.monotonic()
    try:
        async with asyncio.timeout(max(0, job.deadline - start)):
            async for chunk in request.stream():
                rec["bytes"] += len(chunk)
                if rec["bytes"] > job.limits["bytes"]:
                    raise HTTPException(413)
                await pace(start, rec["bytes"], job)
        if rec["bytes"] != job.limits["bytes"]:
            raise HTTPException(400)
        rec["complete"] = True
    except TimeoutError:
        raise HTTPException(408) from None
    finally:
        finish(job, rec, start)
    return rec


@app.get(BASE + "/status")
async def status(sid: UUID, request: Request):
    return current(sid, request).counts


Direction = Literal["download", "upload"]


@app.api_route(BASE + "/blocks/{direction}/{index}", methods=["GET", "POST"])
async def block(sid: UUID, direction: Direction, index: int, request: Request,
                n: int = Query(ge=65536, le=1048576)):
    job = current(sid, request)
    if job.limits.get("mode") != "windowed" or not 0 <= index < 8192:
        raise HTTPException(422)
    upload = direction == "upload"
    if request.method != ("POST" if upload else "GET"):
        raise HTTPException(405)
    if upload and (request.headers.get("content-length") != str(n) or request.headers.get("content-encoding")):
        raise HTTPException(413)
    if direction in job.counts or (job.batch and job.batch.name != direction):
        raise HTTPException(409)
    if job.batch is None:
        job.batch = Batch(direction)
        job.busy = True
    batch = job.batch
    if index in batch.indices or batch.pending >= job.limits["streams"]:
        raise HTTPException(409)
    if batch.allocated + n > job.limits["bytes"] or time.monotonic()-batch.started > job.limits["window_ms"]/1000 + 2:
        raise HTTPException(413)
    batch.indices.add(index)
    batch.allocated += n
    batch.pending += 1
    # Reserve bandwidth for all streams on the same monotonic schedule.
    due = batch.started + batch.allocated * 8 / job.limits["rate_bps"]
    try:
        async with asyncio.timeout(max(0, job.deadline - time.monotonic())):
            if upload:
                size = 0
                async for piece in request.stream():
                    size += len(piece)
                    if size > n:
                        raise HTTPException(413)
                if size != n:
                    raise HTTPException(400)
            await asyncio.sleep(max(0, due - time.monotonic()))
            batch.completed += n
            if upload:
                return Response(status_code=204)
            return Response(CAPACITY_PAYLOAD[:n], media_type="application/octet-stream",
                            headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})
    except TimeoutError:
        raise HTTPException(410) from None
    finally:
        batch.pending -= 1


@app.post(BASE + "/commit/{direction}")
async def commit_blocks(sid: UUID, direction: Direction, request: Request):
    job = current(sid, request)
    batch = job.batch
    if not batch or batch.name != direction or batch.pending or batch.completed != batch.allocated:
        raise HTTPException(409)
    if len(batch.indices) != max(batch.indices, default=-1)+1 or not batch.completed:
        raise HTTPException(409)
    record = {"bytes": batch.completed, "complete": True, "duration_ms": (time.monotonic()-batch.started)*1000}
    job.counts[direction] = record
    job.batch = None
    job.busy = False
    return record


@app.post(BASE + "/finish")
async def close(sid: UUID, request: Request):
    global active
    job = current(sid, request)
    if job.busy and (job.batch is None or job.batch.pending):
        raise HTTPException(409)
    print(json.dumps({"event": "transfer_finished", "session_id": str(sid), "transfers": job.counts}), flush=True)
    active = None
    return Response(status_code=204)
