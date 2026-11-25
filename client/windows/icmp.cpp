#include "icmp.hpp"
#include <array>
#include <cstring>
#include <stdexcept>

namespace {
std::string address_text(int family, const void* bytes) {
    char text[INET6_ADDRSTRLEN]{};
    if (!InetNtopA(family, bytes, text, sizeof(text))) {
        throw std::runtime_error("InetNtopA failed");
    }
    return text;
}

Reply classify(DWORD code, std::string responder, DWORD rtt) {
    if (code == IP_REQ_TIMED_OUT) return {"timeout", code, {}};
    if (responder.empty()) return {"unavailable", code, {}};
    switch (code) {
    case IP_SUCCESS: return {"echo_reply", code, responder, rtt};
    case IP_TTL_EXPIRED_TRANSIT: return {"ttl_expired", code, responder, rtt};
    case IP_DEST_NET_UNREACHABLE:
    case IP_DEST_HOST_UNREACHABLE:
    case IP_DEST_PROT_UNREACHABLE:
    case IP_DEST_PORT_UNREACHABLE:
        return {"unreachable", code, responder, rtt};
    default: return {"unavailable", code, {}};
    }
}
}

Target parse_target(const char* text) {
    Target target;
    auto& v4 = target.address.Ipv4;
    auto& v6 = target.address.Ipv6;
    if (InetPtonA(AF_INET, text, &v4.sin_addr) == 1) {
        auto address = ntohl(v4.sin_addr.s_addr);
        if (address == 0 || address >= 0xe0000000u) throw std::invalid_argument("IPv4 unicast required");
        v4.sin_family = AF_INET;
        target.text = address_text(AF_INET, &v4.sin_addr);
    } else if (InetPtonA(AF_INET6, text, &v6.sin6_addr) == 1) {
        auto& address = v6.sin6_addr;
        if (IN6_IS_ADDR_UNSPECIFIED(&address) || IN6_IS_ADDR_MULTICAST(&address) ||
            IN6_IS_ADDR_LINKLOCAL(&address) || IN6_IS_ADDR_V4MAPPED(&address)) {
            throw std::invalid_argument("unscoped IPv6 unicast required");
        }
        v6.sin6_family = AF_INET6;
        target.text = address_text(AF_INET6, &address);
    } else {
        throw std::invalid_argument("numeric IPv4 or IPv6 address required");
    }
    return target;
}

bool public_game_target(const Target& target) {
    if (target.ipv6()) {
        const auto* bytes=target.address.Ipv6.sin6_addr.s6_addr;
        if ((bytes[0] & 0xe0)!=0x20) return false;
        if (bytes[0]==0x20 && bytes[1]==0x01) {
            if (bytes[2]<2 || (bytes[2]==0x0d && bytes[3]==0xb8)) return false;
        }
        return !(bytes[0]==0x20 && bytes[1]==0x02) && !(bytes[0]==0x3f && bytes[1]==0xff && (bytes[2]&0xf0)==0);
    }
    const auto ip=ntohl(target.address.Ipv4.sin_addr.s_addr);
    auto a=ip>>24, b=(ip>>16)&255, c=(ip>>8)&255;
    return a!=0 && a!=10 && a!=127 && a<224 && !(a==100 && b>=64 && b<=127) &&
        !(a==169 && b==254) && !(a==172 && b>=16 && b<=31) && !(a==192 && b==168) &&
        !(a==192 && ((b==0 && (c==0 || c==2)) || (b==88 && c==99))) &&
        !(a==198 && (b==18 || b==19 || (b==51 && c==100))) && !(a==203 && b==0 && c==113);
}

Probe::Probe(const Target& target) : target_(target) {
    if (target.ipv6()) {
        MIB_IPFORWARD_ROW2 route{};
        setup_error_ = GetBestRoute2(nullptr, 0, nullptr, &target_.address, 0, &route, &source_);
        if (setup_error_) return;
    }
    handle_ = target.ipv6() ? Icmp6CreateFile() : IcmpCreateFile();
    if (handle_ == INVALID_HANDLE_VALUE) setup_error_ = GetLastError();
}

Probe::~Probe() {
    if (handle_ != INVALID_HANDLE_VALUE) IcmpCloseHandle(handle_);
}

Reply Probe::send(unsigned ttl, unsigned timeout_ms) {
    if (setup_error_) return {"unavailable", setup_error_, {}};
    alignas(16) std::array<unsigned char, 1024> buffer{};
    std::array<unsigned char, 32> payload{};
    IP_OPTION_INFORMATION options{};
    options.Ttl = static_cast<UCHAR>(ttl);
    if (target_.ipv6()) {
        auto count = Icmp6SendEcho2(handle_, nullptr, nullptr, nullptr, &source_.Ipv6,
            &target_.address.Ipv6, payload.data(), static_cast<WORD>(payload.size()), &options,
            buffer.data(), static_cast<DWORD>(buffer.size()), timeout_ms);
        if (!count) return classify(GetLastError(), {}, 0);
        auto& reply = *reinterpret_cast<const ICMPV6_ECHO_REPLY*>(buffer.data());
        IN6_ADDR address{};
        std::memcpy(&address, reply.Address.sin6_addr, sizeof(address));
        auto responder = IN6_IS_ADDR_UNSPECIFIED(&address) ? std::string{} : address_text(AF_INET6, &address);
        return classify(reply.Status, responder, reply.RoundTripTime);
    }
    auto count = IcmpSendEcho2(handle_, nullptr, nullptr, nullptr, target_.address.Ipv4.sin_addr.s_addr,
        payload.data(), static_cast<WORD>(payload.size()), &options, buffer.data(),
        static_cast<DWORD>(buffer.size()), timeout_ms);
    if (!count) return classify(GetLastError(), {}, 0);
    auto& reply = *reinterpret_cast<const ICMP_ECHO_REPLY*>(buffer.data());
    auto responder = reply.Address ? address_text(AF_INET, &reply.Address) : std::string{};
    return classify(reply.Status, responder, reply.RoundTripTime);
}
