"""Interpret application transaction latency under verified HTTPS payload load."""

from math import ceil
from statistics import median

VERSION = "0.4.0"


def confirmed_bytes(profile, client_bytes, node_bytes):
    if not profile or not client_bytes or client_bytes != node_bytes:
        return False
    if profile.get("mode") == "windowed":
        return client_bytes <= profile["bytes"]
    return client_bytes == profile["bytes"]


def interpret(doc):
    phases = {}
    for phase, rows in doc["phases"].items():
        times = sorted(r["ms"] for r in rows if r["ms"] is not None and r["error"] is None)
        phases[phase] = {"sent": len(rows), "received": len(times),
                         "median_ms": median(times) if times else None,
                         "p95_ms": times[ceil(len(times) * 0.95) - 1] if times else None}

    def sufficient(name):
        phase = phases[name]
        return phase["received"] >= 5 and phase["received"] >= 0.8 * phase["sent"]

    directions = {}
    for name, transfer in doc["transfers"].items():
        size = transfer["client_bytes"]
        valid = (transfer["status"] == "ok" and confirmed_bytes(doc["profile"], size, transfer["node_bytes"])
                 and transfer["duration_ms"] and transfer["duration_ms"] > 0)
        result = {"goodput_mbps": size * 0.008 / transfer["duration_ms"] if valid else None,
                  "median_increase_ms": None, "status": "unavailable", "reason": "transfer_incomplete"}
        if valid and sufficient("baseline") and sufficient(name):
            delta = phases[name]["median_ms"] - phases["baseline"]["median_ms"]
            result.update(median_increase_ms=delta, reason=None,
                          status="elevated_under_load" if delta >= 20 else "no_elevation_at_measured_rate")
        elif valid:
            result["reason"] = "insufficient_latency_samples"
        directions[name] = result
    recovery = None
    if sufficient("baseline") and sufficient("recovery"):
        recovery = phases["recovery"]["median_ms"] - phases["baseline"]["median_ms"]
    for result in directions.values():
        status = result["status"]
        diagnosis = "inconclusive"
        if status == "no_elevation_at_measured_rate":
            diagnosis = "not_observed_at_measured_rate"
        elif status == "elevated_under_load" and recovery is not None and abs(recovery) < 10:
            diagnosis = "possible_bufferbloat"
        result["bufferbloat"] = diagnosis
    version = "0.5.1" if (doc["profile"] or {}).get("mode") == "windowed" else VERSION
    return {"rules_version": version, "latency_metric": "https_head_transaction_ms",
            "phases": phases, "directions": directions, "recovery_minus_baseline_ms": recovery}
