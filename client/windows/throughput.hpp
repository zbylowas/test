#pragma once
#include "inventory.hpp"
#include <atomic>
#include <functional>

class Queue;
struct LiveTraffic {
    std::atomic<unsigned long long> received{}, sent{};
    std::atomic<unsigned long long> profile_bps{};
};
using PhaseMtr = std::function<void(const Target&, const std::string&, const std::atomic_bool&)>;
Json measure_throughput(Queue&, const std::string&, const std::atomic_bool&, const PhaseMtr&,
                        std::string* observed_ip = nullptr, LiveTraffic* live = nullptr);
std::wstring register_desktop_client(const std::wstring& origin);
Json run_desktop_test(const std::atomic_bool& cancel,
                      const std::function<void(const std::string&)>& progress, LiveTraffic& live);
