#include "icmp.hpp"
#include <chrono>

namespace {
struct Socket {
    SOCKET value;
    ~Socket() { if (value != INVALID_SOCKET) closesocket(value); }
};

}

Reply tcp_probe(Target dest, int ttl, unsigned timeout_ms) {
    auto start = std::chrono::steady_clock::now();
    auto elapsed = [&] { return static_cast<DWORD>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start).count()); };
    auto local_error = [] { return Reply{"unavailable", static_cast<DWORD>(WSAGetLastError()), {}}; };
    Socket sock{socket(dest.address.si_family, SOCK_STREAM, IPPROTO_TCP)};
    if (sock.value == INVALID_SOCKET) return local_error();
    if (WSASetFailConnectOnIcmpError(sock.value, TRUE) == SOCKET_ERROR) return local_error();
    auto level = dest.ipv6() ? IPPROTO_IPV6 : IPPROTO_IP;
    auto option = dest.ipv6() ? IPV6_UNICAST_HOPS : IP_TTL;
    if (setsockopt(sock.value, level, option, reinterpret_cast<const char*>(&ttl), sizeof(ttl)))
        return local_error();
    u_long nonblocking = 1;
    if (ioctlsocket(sock.value, FIONBIO, &nonblocking)) return local_error();
    if (dest.ipv6()) dest.address.Ipv6.sin6_port = htons(443);
    else dest.address.Ipv4.sin_port = htons(443);
    int len = dest.ipv6() ? sizeof(sockaddr_in6) : sizeof(sockaddr_in);
    int error = 0;
    if (connect(sock.value, reinterpret_cast<sockaddr*>(&dest.address), len) == SOCKET_ERROR)
        error = WSAGetLastError();
    if (error == WSAEWOULDBLOCK) {
        fd_set writable{}, failed{};
        FD_SET(sock.value, &writable);
        FD_SET(sock.value, &failed);
        timeval timeout{static_cast<long>(timeout_ms / 1000), static_cast<long>(timeout_ms % 1000) * 1000};
        auto ready = select(0, nullptr, &writable, &failed, &timeout);
        if (ready == SOCKET_ERROR) return local_error();
        if (!ready) return {"timeout", WSAETIMEDOUT, {}};
        int size = sizeof(error);
        if (getsockopt(sock.value, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&error), &size))
            return local_error();
    }
    if (!error || error == WSAECONNREFUSED)
        return {error ? "tcp_refused" : "tcp_connected", static_cast<DWORD>(error), dest.text, elapsed()};
    if (error == WSAETIMEDOUT) return {"timeout", WSAETIMEDOUT, {}};
    if (error == WSAEHOSTUNREACH || error == WSAENETUNREACH) {
        ICMP_ERROR_INFO info{};
        if (WSAGetIcmpErrorInfo(sock.value, &info) == 0 &&
            info.srcaddress.si_family == dest.address.si_family) {
            const void* addr = info.srcaddress.si_family == AF_INET
                ? static_cast<const void*>(&info.srcaddress.Ipv4.sin_addr)
                : static_cast<const void*>(&info.srcaddress.Ipv6.sin6_addr);
            char text[INET6_ADDRSTRLEN]{};
            if (InetNtopA(info.srcaddress.si_family, addr, text, sizeof(text))) {
                const bool expired = info.type == (dest.ipv6() ? 3 : 11) && info.code == 0;
                const bool unreachable = info.type == (dest.ipv6() ? 1 : 3);
                if (expired || unreachable)
                    return {expired ? "ttl_expired" : "unreachable", static_cast<DWORD>(error), text, elapsed()};
            }
        }
    }
    return {"unavailable", static_cast<DWORD>(error), {}};
}
