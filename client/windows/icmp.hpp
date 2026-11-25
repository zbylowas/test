#pragma once

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <string>

struct Target {
    SOCKADDR_INET address{};
    std::string text;
    bool ipv6() const { return address.si_family == AF_INET6; }
};

struct Reply {
    std::string status;
    DWORD code;
    std::string responder;
    DWORD rtt_ms{};
};

Reply tcp_probe(Target target, int ttl, unsigned timeout_ms);
Target parse_target(const char* text);
bool public_game_target(const Target& target);
class Probe {
public:
    explicit Probe(const Target& target);
    ~Probe();
    Probe(const Probe&) = delete;
    Probe& operator=(const Probe&) = delete;
    Reply send(unsigned ttl, unsigned timeout_ms);
private:
    Target target_;
    HANDLE handle_{INVALID_HANDLE_VALUE};
    SOCKADDR_INET source_{};
    DWORD setup_error_{};
};
