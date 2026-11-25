// Stage-0 experiment: one HTTPS port, one unicast address, at most eight connects.
#include "icmp.hpp"
#include <chrono>
#include <iostream>
#include <thread>

int main(int argc, char** argv) {
    if (argc != 2) return 2;
    WSADATA data{};
    if (WSAStartup(MAKEWORD(2, 2), &data)) return 1;
    int result = 0;
    try {
        auto target = parse_target(argv[1]);
        for (int ttl = 1; ttl <= 8; ++ttl) {
            std::cout << "{\"ttl\":" << ttl << ",";
            auto reply = tcp_probe(target, ttl, 1000);
            auto error = reply.code;
            if (!reply.responder.empty()) std::cout << "\"responder\":\"" << reply.responder << "\",";
            std::cout << "\"winsock_code\":" << error << "}" << std::endl;
            if (!error || error == WSAECONNREFUSED) break;
            if (error != WSAETIMEDOUT && error != WSAEHOSTUNREACH) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(150));
        }
    } catch (const std::exception& e) {
        std::cerr << e.what() << '\n';
        result = 1;
    }
    WSACleanup();
    return result;
}
