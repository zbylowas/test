import hashlib
import ipaddress
import os
import secrets
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from uuid import UUID, uuid4

from fastapi import Request
from sqlalchemy import text

from server.database import audit, engine, run


class Problem(Exception):
    def __init__(self, status, code, detail, retry=None):
        super().__init__(detail)
        self.status, self.code, self.detail, self.retry = status, code, detail, retry


@dataclass(frozen=True)
class Actor:
    id: UUID
    tenant: UUID
    role: str
    source: str


_peers = OrderedDict()
_peer_lock = threading.Lock()


def admit(source):
    # Per-process protection before queries for unrecognised bearer tokens.
    minute = int(time.monotonic() // 60)
    with _peer_lock:
        previous, count = _peers.get(source, (minute, 0))
        count = count + 1 if previous == minute else 1
        _peers[source] = minute, count
        _peers.move_to_end(source)
        if len(_peers) > 4096:
            _peers.popitem(last=False)
    if count > int(os.getenv("VIPNET_PEER_REQUESTS_PER_MINUTE", "900")):
        raise Problem(429, "peer_limit", "Limit żądań z adresu źródłowego.", 60)


def source_address(request):
    try:
        peer = ipaddress.ip_address(request.client.host)
        trusted = [
            ipaddress.ip_network(s.strip())
            for s in os.getenv("VIPNET_TRUSTED_PROXIES", "").split(",")
            if s.strip()
        ]
        secure = request.url.scheme == "https"
        if any(peer in net for net in trusted):
            # The configured edge must overwrite BOTH incoming headers with single values.
            forwarded = request.headers.getlist("x-forwarded-for")
            if len(forwarded) != 1:
                raise ValueError("one source required")
            peer = ipaddress.ip_address(forwarded[0])
            secure = request.headers.getlist("x-forwarded-proto") == ["https"]
    except (ValueError, KeyError, AttributeError):
        raise Problem(400, "invalid_peer", "Niepoprawny adres połączenia.")
    if not secure:
        raise Problem(403, "tls_required", "Wymagane HTTPS.")
    return str(peer)


def authenticate(request: Request):
    source = source_address(request)
    admit(source)
    prefix, _, token = request.headers.get("authorization", "").partition(" ")
    if prefix.lower() != "bearer" or not 32 <= len(token) <= 256:
        raise Problem(401, "unauthorized", "Wymagany token.")
    digest = hashlib.sha256(token.encode()).digest()
    with engine().begin() as conn:
        row = (
            run(
                conn,
                """SELECT id,tenant,role FROM security.principal
                    WHERE enabled AND token_hash=:digest""",
                digest=digest,
            )
            .mappings()
            .first()
        )
        if not row:
            raise Problem(401, "unauthorized", "Nieprawidłowy token.")
        allowed = run(
            conn,
            """UPDATE security.principal SET rate_minute=date_trunc('minute',now()),
                  rate_count=CASE WHEN rate_minute=date_trunc('minute',now()) THEN rate_count+1 ELSE 1 END
                  WHERE id=:id AND enabled AND (rate_minute IS DISTINCT FROM date_trunc('minute',now())
                        OR rate_count < :quota) RETURNING id""",
            id=row["id"],
            quota=int(os.getenv("VIPNET_REQUESTS_PER_MINUTE", "300")),
        ).first()
        if not allowed:
            raise Problem(429, "rate_limit", "Limit żądań.", 60)
    return Actor(**row, source=source)


def provision(tenant, role):
    if role not in {"client", "operator"}:
        raise ValueError("invalid role")
    token = secrets.token_urlsafe(32)
    principal = uuid4()
    with engine().begin() as conn:
        conn.execute(
            text("""INSERT INTO security.principal(id,tenant,role,token_hash)
                      VALUES (:id,:tenant,:role,:digest)"""),
            dict(id=principal, tenant=tenant, role=role, digest=hashlib.sha256(token.encode()).digest()),
        )
        audit(conn, principal, None, "credential.issue")
    return principal, token


def change_token(principal, rotate):
    token = secrets.token_urlsafe(32) if rotate else None
    with engine().begin() as conn:
        if rotate:
            changed = run(
                conn,
                """UPDATE security.principal SET token_hash=:digest WHERE id=:id AND enabled""",
                digest=hashlib.sha256(token.encode()).digest(),
                id=principal,
            )
        else:
            changed = run(
                conn, "UPDATE security.principal SET enabled=false WHERE id=:id AND enabled", id=principal
            )
        if changed.rowcount != 1:
            raise ValueError("Brak aktywnej tożsamości.")
        audit(conn, principal, None, "credential.rotate" if rotate else "credential.revoke")
    return token
