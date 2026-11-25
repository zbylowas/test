"""Interpret one schema-validated target, protocol and phase at a time."""
from collections import defaultdict
from ipaddress import ip_address
from math import ceil
from statistics import fmean, pstdev

VERSION = "0.1.0"
MIN_ATTEMPTS = 5
RESPONSES = {"echo_reply", "ttl_expired", "unreachable"}


def hop_statistics(samples, responses=RESPONSES):
    ordered = sorted(samples, key=lambda row: row["attempt"])
    sent = [row for row in ordered if row["status"] != "unavailable"]
    replies = [r for r in sent if r["status"] in responses]
    rtts = sorted(r["rtt_ms"] for r in replies)
    deltas = [abs(b["rtt_ms"] - a["rtt_ms"]) for a, b in zip(replies, replies[1:])
              if b["attempt"] == a["attempt"] + 1 and a["responder"] == b["responder"]]

    def percentile(p):
        return rtts[ceil(len(rtts) * p) - 1] if rtts else None

    return {
        "snt": len(sent), "rcv": len(replies), "unavailable": len(ordered) - len(sent),
        "loss_pct": 100 * (len(sent) - len(replies)) / len(sent) if sent else None,
        "last": ordered[-1]["rtt_ms"] if ordered else None,
        "best": min(rtts, default=None), "avg": fmean(rtts) if rtts else None,
        "worst": max(rtts, default=None), "stdev": pstdev(rtts) if rtts else None,
        "p50": percentile(.5), "p95": percentile(.95), "p99": percentile(.99),
        "mean_abs_delta_ms": fmean(deltas) if deltas else None,
        "responders": sorted({r["responder"] for r in replies}),
    }


def finding(rule, severity, confidence, evidence, limitations, followup):
    return {"rule_id": rule, "version": VERSION, "severity": severity, "confidence": confidence,
            "evidence": evidence, "limitations": limitations, "recommended_tests": [followup]}


def analyze(samples):
    rows = list(samples)
    keys = {(r["session_id"], r["target"], r["family"], r["protocol"], r["phase"]) for r in rows}
    if len(keys) > 1:
        raise ValueError("mixed measurements")
    if rows and rows[0]["protocol"] != "icmp":
        raise ValueError("rules version 0.1.0 requires ICMP")
    if len({(r["ttl"], r["attempt"]) for r in rows}) != len(rows):
        raise ValueError("duplicate sample")
    by_ttl = defaultdict(list)
    for row in rows:
        by_ttl[row["ttl"]].append(row)

    stats = {ttl: hop_statistics(by_ttl[ttl]) for ttl in sorted(by_ttl)}
    attempts = {r["attempt"] for r in rows}
    reached = [r for r in rows if r["status"] == "echo_reply" and
               ip_address(r["responder"]) == ip_address(r["target"])]
    terminal_ttls = {r["ttl"] for r in reached}
    diagnoses = []
    if len(attempts) < MIN_ATTEMPTS or not any(s["snt"] >= MIN_ATTEMPTS for s in stats.values()):
        diagnoses.append(finding("sample.insufficient", "info", "high", {"attempts": len(attempts)},
                                 "Mała seria ogranicza ocenę strat.", "Powtórz co najmniej pięć rund."))
        return stats, diagnoses

    if not reached:
        diagnoses.append(finding("destination.unconfirmed", "warning", "medium",
                                 {"attempts": len(attempts), "highest_ttl": max(stats)},
                                 "Limit TTL, filtrowanie i niepełny zapis mogą ukryć cel.",
                                 "Sprawdź większy limit TTL i dostępność usługi."))
    for ttl, hop in stats.items():
        if len(hop["responders"]) > 1:
            diagnoses.append(finding("route.multiple_responders", "info", "high",
                                     {"ttl": ttl, "addresses": hop["responders"]},
                                     "Możliwe ECMP lub zmiana trasy w czasie.", "Porównaj kolejne pełne ścieżki."))
    if len(terminal_ttls) != 1:
        return stats, diagnoses

    terminal = next(iter(terminal_ttls))
    end = stats[terminal]
    observed = by_ttl[terminal]
    if {r["attempt"] for r in observed} != attempts or end["snt"] != len(attempts):
        return stats, diagnoses
    if any(r["status"] != "timeout" and r not in reached for r in observed):
        return stats, diagnoses

    if len(reached) < len(attempts):
        diagnoses.append(finding("destination.missing_replies", "warning", "medium",
                                 {"ttl": terminal, "echo_replies": len(reached), "snt": end["snt"]},
                                 "Brak echa nie rozstrzyga o stratach ruchu aplikacyjnego.",
                                 "Porównaj połączenia TCP oraz kolejną serię ICMP."))
        return stats, diagnoses

    for ttl, hop in stats.items():
        if ttl >= terminal or hop["snt"] != len(attempts) or hop["rcv"] == hop["snt"]:
            continue
        if any(r["status"] not in {"ttl_expired", "timeout"} for r in by_ttl[ttl]):
            continue
        rule = "hop.silent" if hop["rcv"] == 0 else "hop.possible_icmp_limiting"
        diagnoses.append(finding(rule, "info", "medium",
                                 {"ttl": ttl, "snt": hop["snt"], "rcv": hop["rcv"], "destination_rcv": len(reached)},
                                 "Router może filtrować ICMP lub ograniczać częstość odpowiedzi.",
                                 "Powtórz serię w dłuższych odstępach."))
    return stats, diagnoses
