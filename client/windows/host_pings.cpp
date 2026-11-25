#include "host_pings.hpp"
#include "queue.hpp"
#include <chrono>
#include <optional>
#include <thread>

namespace {
std::string numeric(const SOCKADDR_INET& address) {
    char buffer[INET6_ADDRSTRLEN]{};
    const void* bytes = address.si_family == AF_INET ? static_cast<const void*>(&address.Ipv4.sin_addr)
                                                     : static_cast<const void*>(&address.Ipv6.sin6_addr);
    return InetNtopA(address.si_family,bytes,buffer,sizeof buffer) ? buffer : "";
}

std::optional<Target> next_router(const Target& peer, const std::string& reserved_ip, std::string& reason) {
    MIB_IPFORWARD_ROW2 best{};
    SOCKADDR_INET source{};
    const DWORD error=GetBestRoute2(nullptr,0,nullptr,&peer.address,0,&best,&source);
    if (error || numeric(source)!=reserved_ip) {
        reason=error ? "route_lookup_failed" : "route_changed";
        return {};
    }
    Target router{best.NextHop,numeric(best.NextHop)};
    if (router.address.si_family!=peer.address.si_family || router.text.empty() ||
        router.text=="::" || router.text=="0.0.0.0" || router.text==peer.text) {
        reason="no_separate_gateway"; return {};
    }
    if (router.ipv6() && IN6_IS_ADDR_LINKLOCAL(&router.address.Ipv6.sin6_addr)) {
        if (!best.InterfaceIndex) { reason="missing_interface_scope"; return {}; }
        router.address.Ipv6.sin6_scope_id=best.InterfaceIndex;
        return router;
    }
    try { return parse_target(router.text.c_str()); }
    catch (const std::invalid_argument&) { reason="invalid_gateway"; return {}; }
}
}

void measure_host_pings(Json& transfer,const std::atomic_bool& cancel,const std::function<void()>& checkpoint) {
    const Json empty={{"target",nullptr},{"planned",5},{"timeout_ms",400},{"reason","no_reservation"},{"samples",Json::array()}};
    auto& hosts=transfer["host_pings"];
    hosts={{"node",empty},{"gateway",empty}};
    if (!transfer.at("peer").is_string()) { checkpoint(); return; }
    auto node=parse_target(transfer.at("peer").get<std::string>().c_str());
    std::string reason;
    auto router=next_router(node,transfer.at("reservation_local_ip").value("value",std::string{}),reason);
    hosts["node"]["target"]=node.text;
    hosts["node"]["reason"]="interrupted";
    hosts["gateway"]["reason"]=router ? "interrupted" : reason;
    if (router) hosts["gateway"]["target"]=router->text;
    checkpoint();
    auto measure=[&](const char* role,const Target& target) {
        Probe probe(target);
        auto& host=hosts[role];
        for (int i=0; i<5 && !cancel; ++i) {
            auto at=utc_now();
            auto reply=probe.send(64,400);
            if (reply.status=="echo_reply" && reply.responder!=target.text) reply.status="other_responder";
            host["samples"].push_back({{"at",at},{"status",reply.status},{"native_code",reply.code},
                {"responder",reply.responder.empty()?Json(nullptr):Json(reply.responder)},
                {"rtt_ms",reply.status=="echo_reply"?Json(reply.rtt_ms):Json(nullptr)}});
            checkpoint();
            if (i<4 && !cancel) std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        host["reason"]=host["samples"].size()==5 ? Json(nullptr) : Json("cancelled");
        checkpoint();
    };
    if (router) measure("gateway",*router);
    measure("node",node);
}
