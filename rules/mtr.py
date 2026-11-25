"""Deterministic MTR interpretation for one measurement session."""

from collections import defaultdict
from datetime import datetime
from ipaddress import ip_address
from itertools import groupby
from statistics import median

from rules.v010 import MIN_ATTEMPTS
from rules.v010 import hop_statistics as statistics

VERSION = "0.2.0"
TERMINAL = {"echo_reply", "tcp_connected", "tcp_refused"}
RESPONSES = TERMINAL | {"ttl_expired", "unreachable"}
STEP_MS = 20


def hop_statistics(rows):
    return statistics(rows, RESPONSES)


def finding(rule, severity, confidence, evidence, limitations, test):
    return {
        "rule_id": rule,
        "version": VERSION,
        "severity": severity,
        "confidence": confidence,
        "evidence": evidence,
        "limitations": limitations,
        "recommended_tests": [test],
    }


def reached(row):
    return row["status"] in TERMINAL and ip_address(row["responder"]) == ip_address(row["target"])


def analyze(samples, networks=None):
    """networks is an optional operator mapping of exact router addresses to network IDs."""
    rows = sorted(samples, key=lambda r: (r["ttl"], r["attempt"]))
    series = {
        (r["session_id"], r["target"], r["family"], r["protocol"], r["phase"], r.get("tcp_port"))
        for r in rows
    }
    if len(series) > 1:
        raise ValueError("mixed measurements")
    hops = defaultdict(dict)
    for r in rows:
        ttl, attempt = r["ttl"], r["attempt"]
        if attempt in hops[ttl]:
            raise ValueError("duplicate sample")
        hops[ttl][attempt] = r
    stats = {ttl: hop_statistics(rounds.values()) for ttl, rounds in hops.items()}
    diagnoses = []

    def add(*args):
        diagnoses.append(finding(*args))

    attempts = {r["attempt"] for r in rows}
    arrivals = [r for r in rows if reached(r)]
    if len(attempts) < MIN_ATTEMPTS or not any(h["snt"] >= MIN_ATTEMPTS for h in stats.values()):
        add(
            "sample.insufficient",
            "info",
            "high",
            {"attempts": len(attempts), "sent_by_ttl": {k: v["snt"] for k, v in stats.items()}},
            "Lokalny błąd API i brak rund ograniczają ocenę.",
            "Powtórz co najmniej pięć rund z działającym interfejsem.",
        )
    if rows and rows[0]["family"] == 6:
        codes = sorted(
            {
                r["native_code"]
                for r in rows
                if r["status"] == "unavailable" and r.get("native_code") in {11045, 1231, 10051}
            }
        )
        if codes and not arrivals:
            add(
                "ipv6.local_route",
                "warning",
                "high",
                {"native_codes": codes},
                "Kod dotyczy trasy lub zakresu na tej stacji.",
                "Sprawdź źródłowy IPv6, zakres i tablicę routingu.",
            )
    if not rows or any(d["rule_id"] == "sample.insufficient" for d in diagnoses):
        return stats, diagnoses
    if not arrivals:
        explicit = [r for r in rows if r["status"] == "unreachable"]
        confirmed = len({r["attempt"] for r in explicit}) >= MIN_ATTEMPTS
        add(
            "destination.unreachable" if confirmed else "destination.unconfirmed",
            "warning",
            "medium" if confirmed else "low",
            {
                "highest_ttl": max(stats),
                "explicit_rounds": sorted({r["attempt"] for r in explicit}),
                "attempts": len(attempts),
            },
            "Komunikat routera, filtr lub limit TTL ogranicza wniosek o dostępności hosta.",
            "Sprawdź usługę i trasę z drugiego punktu.",
        )
    for ttl, rounds in hops.items():
        if len(stats[ttl]["responders"]) < 2:
            continue
        add(
            "route.multiple_responders",
            "info",
            "high",
            {"ttl": ttl, "addresses": stats[ttl]["responders"]},
            "Adres interfejsu może zależeć od drogi powrotnej.",
            "Porównaj sekwencje rund i protokoły.",
        )
        if set(rounds) != attempts or any(r["status"] != "ttl_expired" for r in rounds.values()):
            continue
        if sorted(rounds) != list(range(min(rounds), max(rounds) + 1)):
            continue
        runs = [(addr, len(list(g))) for addr, g in groupby(r["responder"] for r in rounds.values())]
        evidence = {"ttl": ttl, "runs": runs}
        if len(runs) == 2 and min(n for _, n in runs) >= 2:
            add(
                "route.change",
                "info",
                "medium",
                evidence,
                "Dwa stabilne odcinki są również możliwe przy ECMP.",
                "Powtórz pomiar i sprawdź historię routingu.",
            )
        if len(runs) >= 4 and any(sum(1 for addr, _ in runs if addr == v) >= 2 for v, _ in runs):
            add(
                "route.possible_ecmp",
                "info",
                "medium",
                evidence,
                "Przeplot dróg może też wynikać z krótkich zmian tras.",
                "Powtórz serię przy stałych parametrach przepływu.",
            )

    for ttl in hops:
        if not all(k in hops for k in range(ttl, ttl + 4)):
            continue
        matched = []
        for a in sorted(attempts):
            block = [hops[k].get(a) for k in range(ttl, ttl + 4)]
            if not all(r and r["status"] == "ttl_expired" for r in block):
                continue
            x, y, z, w = [r["responder"] for r in block]
            if x == z and y == w and x != y:
                matched.append(a)
        if len(matched) >= MIN_ATTEMPTS:
            add(
                "route.possible_loop",
                "warning",
                "medium",
                {"ttl": ttl, "rounds": matched},
                "Powtarzalne A–B–A–B może także wynikać z różnych ścieżek prób.",
                "Sprawdź z drugiego węzła i porównaj routing.",
            )
            break

    ends = {r["ttl"] for r in arrivals}
    if len(ends) != 1:
        return stats, diagnoses
    end = ends.pop()

    def complete(ttl):
        return ttl in hops and set(hops[ttl]) == attempts and stats[ttl]["snt"] == len(attempts)

    if not complete(end) or any(not reached(r) and r["status"] != "timeout" for r in hops[end].values()):
        return stats, diagnoses
    missing = {a for a, r in hops[end].items() if r["status"] == "timeout"}
    if missing:
        add(
            "destination.missing_replies",
            "warning",
            "medium",
            {"ttl": end, "missing_rounds": sorted(missing), "sent": len(attempts)},
            "Brak odpowiedzi na próbę może wynikać z filtrowania.",
            "Powtórz pomiar i porównaj niezależny protokół.",
        )
        if len(missing) >= 2:
            first = end
            for ttl in range(end - 1, 0, -1):
                if (
                    not complete(ttl)
                    or any(r["status"] not in {"timeout", "ttl_expired"} for r in hops[ttl].values())
                    or not all(hops[ttl][a]["status"] == "timeout" for a in missing)
                ):
                    break
                first = ttl
            if first < end:
                add(
                    "loss.persistent_to_target",
                    "warning",
                    "medium",
                    {"from_ttl": first, "end_ttl": end, "rounds": sorted(missing)},
                    "Każdy TTL to osobna próba. Zbieżność rund nie lokalizuje uszkodzenia.",
                    "Sprawdź równolegle sesję aplikacyjną.",
                )
        return stats, diagnoses

    for ttl, hop in stats.items():
        if (
            ttl < end
            and complete(ttl)
            and hop["rcv"] < hop["snt"]
            and (hop["rcv"] == 0 or rows[0]["protocol"] == "icmp")
            and all(r["status"] in {"timeout", "ttl_expired"} for r in hops[ttl].values())
        ):
            add(
                "hop.silent" if not hop["rcv"] else "hop.possible_icmp_limiting",
                "info",
                "medium",
                {"ttl": ttl, "snt": hop["snt"], "rcv": hop["rcv"], "destination_rcv": len(arrivals)},
                "Cel odpowiada we wszystkich rundach. Router może ograniczać odpowiedzi.",
                "Powtórz próby w dłuższych odstępach.",
            )

    def stable(ttl):
        return (
            complete(ttl)
            and len(stats[ttl]["responders"]) == 1
            and all(reached(r) if ttl == end else r["status"] == "ttl_expired" for r in hops[ttl].values())
        )

    stable_hops = {k for k in hops if stable(k)}
    for ttl in range(1, end):
        if not all(k in stable_hops for k in range(max(1, ttl - 1), end + 1)):
            continue

        baseline = {a: hops[ttl - 1][a]["rtt_ms"] if ttl > 1 else 0 for a in attempts}

        def elevated(k, a, reference=baseline):
            return hops[k][a]["rtt_ms"] - reference[a] >= STEP_MS

        high = [a for a in sorted(attempts) if all(elevated(k, a) for k in range(ttl, end + 1))]
        if len(high) >= max(MIN_ATTEMPTS, 0.8 * len(attempts)):
            e = {"from_ttl": ttl, "end_ttl": end, "floor_ms": STEP_MS, "rounds": high}
            add(
                "latency.sustained_step",
                "warning",
                "medium",
                e,
                "RTT obejmuje obie strony ścieżki.",
                "Powtórz serię poza szczytem.",
            )
            if ttl == 1:
                add(
                    "lan.possible_delay",
                    "warning",
                    "low",
                    e,
                    "Pierwszy widoczny router może należeć do dostawcy.",
                    "Porównaj bramę lokalną po kablu i Wi-Fi.",
                )
            if networks and ttl > 1:
                before, after = (networks.get(stats[k]["responders"][0]) for k in (ttl - 1, ttl))
                if before and after and before != after:
                    add(
                        "boundary.possible_delay",
                        "warning",
                        "low",
                        e | {"networks": [before, after]},
                        "Mapowanie operatora i skok RTT nie ustalają miejsca kolejkowania.",
                        "Porównaj kierunek powrotny i liczniki styku.",
                    )
        isolated = [
            a
            for a in sorted(attempts)
            if elevated(ttl, a) and all(not elevated(k, a) for k in range(ttl + 1, end + 1))
        ]
        if len(isolated) >= max(MIN_ATTEMPTS, 0.8 * len(attempts)):
            add(
                "latency.isolated_hop",
                "info",
                "medium",
                {"ttl": ttl, "rounds": isolated, "floor_ms": STEP_MS},
                "Na dalszych TTL opóźnienie wraca do poziomu odniesienia.",
                "Sprawdź RTT usługi docelowej.",
            )
    return stats, diagnoses


def endpoint(rows):
    """Return an endpoint summary only for rounds with comparable terminal coverage."""
    rounds = {r["attempt"] for r in rows}
    arrivals = [r for r in rows if reached(r)]
    if len(rounds) < MIN_ATTEMPTS or any(r["status"] == "unavailable" for r in rows):
        return None
    ends = {r["ttl"] for r in arrivals}
    if len(ends) != 1:
        return None
    ttl = ends.pop()
    last = [r for r in rows if r["ttl"] == ttl]
    if {r["attempt"] for r in last} != rounds or any(
        not reached(r) and r["status"] != "timeout" for r in last
    ):
        return None
    return {
        "ttl": ttl,
        "sent": len(rounds),
        "received": len(arrivals),
        "median_ms": median(r["rtt_ms"] for r in arrivals),
    }


def silent_endpoint(rows, ttl):
    rounds = {r["attempt"] for r in rows}
    last = [r for r in rows if r["ttl"] == ttl]
    if (
        len(rounds) >= MIN_ATTEMPTS
        and len(last) == len(rounds)
        and all(r["status"] == "timeout" for r in last)
        and not any(reached(r) or r["status"] == "unavailable" for r in rows)
    ):
        return {"ttl": ttl, "sent": len(last), "received": 0, "median_ms": None}
    return None


def stable_path(rows):
    """Require a complete single address at every depth and the same destination TTL in all rounds."""
    end = endpoint(rows)
    if not end or end["received"] != end["sent"]:
        return None
    path = []
    for ttl in range(1, end["ttl"]):
        hop = [r for r in rows if r["ttl"] == ttl]
        addresses = {r["responder"] for r in hop if r["status"] == "ttl_expired"}
        if len(addresses) != 1 or len(hop) != end["sent"] or any(r["status"] != "ttl_expired" for r in hop):
            return None
        path.append(addresses.pop())
    return path


def interpret(samples, networks=None, dual_stack_pair=None):
    groups = defaultdict(list)
    sessions = set()
    for r in samples:
        sessions.add(r["session_id"])
        groups[r["target"], r["protocol"], r["phase"], r.get("tcp_port", 0)].append(r)
    if len(sessions) > 1:
        raise ValueError("mixed sessions")
    series, findings = [], []
    if not groups:
        return {"sample_count": 0, "series": [], "findings": analyze([])[1]}
    for (target, protocol, phase, port), rows in sorted(groups.items()):
        stats, diagnoses = analyze(rows, networks)
        series.append(
            {
                "target": target,
                "family": ip_address(target).version,
                "protocol": protocol,
                "phase": phase,
                "stats": stats,
                "findings": diagnoses,
            }
        )
        if protocol == "tcp":
            series[-1]["tcp_port"] = port or None
        if phase == "baseline":
            base = endpoint(rows)
            recovery_rows = groups.get((target, protocol, "recovery", port), [])
            recovery = endpoint(recovery_rows)
            for load in ("download", "upload"):
                loaded = groups.get((target, protocol, load, port), [])
                value = endpoint(loaded)
                if not all(x and x["received"] == x["sent"] for x in (base, recovery, value)):
                    continue
                # A refused TCP connect can have different retry timing from a successful handshake.
                terminal_states = {
                    r["status"] for window in (rows, loaded, recovery_rows) for r in window if reached(r)
                }
                if len(terminal_states) != 1:
                    continue
                baseline_end = max(datetime.fromisoformat(r["timestamp"]) for r in rows)
                load_times = [datetime.fromisoformat(r["timestamp"]) for r in loaded]
                recovery_start = min(datetime.fromisoformat(r["timestamp"]) for r in recovery_rows)
                if not baseline_end < min(load_times) <= max(load_times) < recovery_start:
                    continue
                path = stable_path(rows)
                if path is None or path != stable_path(loaded) or path != stable_path(recovery_rows):
                    continue
                delta = value["median_ms"] - base["median_ms"]
                if delta >= STEP_MS and abs(recovery["median_ms"] - base["median_ms"]) < STEP_MS / 2:
                    findings.append(
                        finding(
                            "load.possible_bufferbloat",
                            "warning",
                            "medium",
                            {
                                "target": target,
                                "protocol": protocol,
                                "phase": load,
                                "baseline": base,
                                "loaded": value,
                                "recovery": recovery,
                            },
                            "Zgodność z fazą zadeklarowaną przez kontroler nie lokalizuje kolejki.",
                            "Porównaj drugi kierunek obciążenia i powtórz przewodowo.",
                        )
                    )
        if protocol == "icmp":
            tcp = groups.get((target, "tcp", phase, 443), [])
            if tcp and all(r.get("tcp_port") == 443 for r in tcp):
                a, b = endpoint(rows), endpoint(tcp)
                if a and not b:
                    b = silent_endpoint(tcp, a["ttl"])
                if b and not a:
                    a = silent_endpoint(rows, b["ttl"])
                if (
                    a
                    and b
                    and a["sent"] == b["sent"]
                    and a["ttl"] == b["ttl"]
                    and {r["attempt"] for r in rows} == {r["attempt"] for r in tcp}
                    and abs(a["received"] - b["received"]) >= 2
                ):
                    findings.append(
                        finding(
                            "protocol.divergence",
                            "warning",
                            "medium",
                            {"target": target, "phase": phase, "icmp": a, "tcp443": b},
                            "Echo ICMP i połączenia TCP podlegają innym politykom.",
                            "Sprawdź dostępność aplikacji oraz reguły filtrowania.",
                        )
                    )
    if dual_stack_pair:
        v4, v6 = map(str, map(ip_address, dual_stack_pair))
        if ip_address(v4).version != 4 or ip_address(v6).version != 6:
            raise ValueError("expected a verified IPv4 and IPv6 pair")
        for (target, proto, phase, port), rows in sorted(groups.items()):
            if target != v6:
                continue
            good = endpoint(groups.get((v4, proto, phase, port), []))
            attempts = {r["attempt"] for r in rows}
            covered = {
                r["attempt"]
                for r in rows
                if good and (r["ttl"] >= good["ttl"] or r["status"] == "unreachable")
            }
            if (
                good
                and good["sent"] == good["received"] == len(attempts)
                and not any(reached(r) for r in rows)
                and not any(r["status"] == "unavailable" for r in rows)
                and {r["attempt"] for r in groups[v4, proto, phase, port]} == attempts
                and covered == attempts
            ):
                findings.append(
                    finding(
                        "ipv6.paired_failure",
                        "warning",
                        "medium",
                        {"v4": v4, "v6": v6, "protocol": proto, "phase": phase, "rounds": len(attempts)},
                        "Porównanie pary tej samej usługi zależy od limitu TTL i polityki filtrowania.",
                        "Powtórz przez drugie łącze IPv6.",
                    )
                )
    return {"sample_count": sum(map(len, groups.values())), "series": series, "findings": findings}
