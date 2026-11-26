#pragma once
#include "inventory.hpp"
#include <atomic>
#include <functional>
#include <chrono>
#include <array>
#include <mutex>

class Queue;
struct LiveTraffic {
    std::atomic<unsigned long long> received{}, sent{};
    std::atomic<unsigned long long> profile_bps{};
    bool capacity = true;
    std::function<void(const Json&)> on_measurement_adapter;
    void clear();
    void observe(size_t direction, unsigned long long bytes);
    Json trace(size_t direction) const;
private:
    mutable std::mutex mutex_;
    std::array<Json,2> traces_{Json::array(),Json::array()};
    std::array<std::chrono::steady_clock::time_point,2> starts_{};
};
using PhaseMtr = std::function<void(const Target&, const std::string&, const std::atomic_bool&)>;
Json measure_throughput(Queue&, const std::string&, const std::atomic_bool&, const PhaseMtr&,
                        std::string* observed_ip = nullptr, LiveTraffic* live = nullptr);
std::wstring register_desktop_client(const std::wstring& origin);
Json run_desktop_test(const std::atomic_bool& cancel,
                      const std::function<void(const std::string&)>& progress, LiveTraffic& live);

Json fetch_game_profiles(const std::wstring& origin);
struct RouteRequest {
    std::string purpose,host,profile,protocol,region,target_kind="user_supplied";
    unsigned attempts=20,ttl=16,interval=100,timeout=400;
    bool direct=false;
    int family=0;
};
Json run_route(const RouteRequest&,const std::atomic_bool&,const std::function<void(const Json&)>&);

std::string fetch_release_bytes(const std::wstring& origin, bool executable);
