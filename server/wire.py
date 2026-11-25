import hashlib
import json
import math
import zlib
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from server.access import Problem

BASE = Path(__file__).resolve().parents[1] / "contracts/v1"
DOCUMENTS = {p.name: json.loads(p.read_text(encoding="utf-8")) for p in BASE.glob("*.json")}
registry = Registry().with_resources(
    ((BASE / name).as_uri(), Resource.from_contents(doc))
    for name, doc in DOCUMENTS.items()
    if name.endswith(".schema.json")
)
VALIDATORS = {
    name.split(".")[0]: Draft202012Validator(
        {"$ref": (BASE / name).as_uri()}, registry=registry, format_checker=FormatChecker()
    )
    for name in DOCUMENTS
    if name.endswith(".schema.json")
}
MAX_WIRE, MAX_BODY = 256 * 1024, 1024 * 1024


def unique_keys(pairs):
    obj = dict(pairs)
    if len(obj) != len(pairs):
        raise ValueError("duplicate key")
    return obj


def finite_float(value):
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("non-finite number")
    return result


async def read_body(request):
    if request.headers.get("content-type", "").split(";")[0].strip().lower() != "application/json":
        raise Problem(415, "media_type", "Wymagany application/json.")
    raw = bytearray()
    async for piece in request.stream():
        if len(raw) + len(piece) > MAX_WIRE:
            raise Problem(413, "too_large", "Przekroczono limit transmisji.")
        raw.extend(piece)
    coding = request.headers.get("content-encoding", "identity").lower()
    if coding == "gzip":
        decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
        try:
            raw = decoder.decompress(raw, MAX_BODY + 1)
        except zlib.error:
            raise Problem(422, "gzip", "Niepoprawne gzip.")
        if len(raw) > MAX_BODY:
            raise Problem(413, "too_large", "Przekroczono limit dekompresji.")
        if not decoder.eof or decoder.unused_data:
            raise Problem(422, "gzip", "Niekompletny lub nadmiarowy strumień gzip.")
    elif coding != "identity":
        raise Problem(415, "encoding", "Nieobsługiwane kodowanie.")
    return bytes(raw)


def decode(raw, kind):
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=unique_keys,
            parse_float=finite_float,
            parse_constant=finite_float,
        )
        if not VALIDATORS[kind].is_valid(value):
            raise ValueError("schema")
        # PostgreSQL text/jsonb requires representable Unicode, excluding U+0000.
        if kind == "session" and "\x00" in value["client_version"]:
            raise ValueError("nul in version")
        json.dumps(value, ensure_ascii=False).encode("utf-8")
    except (ValueError, RecursionError, OverflowError):
        raise Problem(422, "validation", "Dane nie spełniają kontraktu v1.")
    return value, hashlib.sha256(raw).digest()
