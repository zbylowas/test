#include "inventory.hpp"
#include "queue.hpp"
#include "throughput.hpp"
#include <psapi.h>
#include <objbase.h>
#include <algorithm>
#include <atomic>
#include <charconv>
#include <chrono>
#include <cstdio>
#include <iostream>
#include <mutex>
#include <optional>
#include <array>
#include <stdexcept>
#include <sstream>
#include <string_view>
#include <thread>
#include <vector>

namespace {
using Clock = std::chrono::steady_clock;
std::atomic_bool cancelled{};
std::mutex output;
BOOL WINAPI stop(DWORD event) {
    if (event != CTRL_C_EVENT && event != CTRL_BREAK_EVENT) return FALSE;
    cancelled.store(true);
    return TRUE;
}

unsigned bounded(const char* text, unsigned low, unsigned high) {
    std::string_view value(text);
    unsigned number{};
    auto parsed = std::from_chars(value.data(), value.data() + value.size(), number);
    if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size() || number < low || number > high)
        throw std::invalid_argument("numeric argument outside allowed range");
    return number;
}

std::string session_id() {
    GUID id{};
    wchar_t wide[39]{};
    if (FAILED(CoCreateGuid(&id)) || !StringFromGUID2(id, wide, 39)) throw std::runtime_error("UUID failed");
    std::string id_text;
    for (int i = 1; i <= 36; ++i) id_text += static_cast<char>(wide[i]);
    return id_text;
}

}

std::string utc_now() {
    SYSTEMTIME t{};
    GetSystemTime(&t);
    char result[40]{};
    std::snprintf(result, sizeof result, "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
        t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond, t.wMilliseconds);
    return result;
}

namespace {
struct Options {
    std::string protocol{"icmp"};
    unsigned interval_ms{100};
    bool phased{};
};

std::string measurement_parameters(const Options& options, const std::vector<Target>& targets,
                                   unsigned attempts, unsigned hops, unsigned timeout) {
    auto version=windows_version();
    std::ostringstream json;
    json << "{\"windows_version\":\"" << (version.empty()?"unavailable:RtlGetVersion":version);
    json << "\",\"attempts\":" << attempts << ",\"max_ttl\":" << hops << ",\"timeout_ms\":" << timeout
         << ",\"interval_ms\":" << options.interval_ms << ",\"protocol\":\"" << options.protocol
         << "\",\"phase_control\":" << (options.phased ? "true" : "false") << ",\"targets\":[";
    for (size_t i = 0; i < targets.size(); ++i) {
        if (i) json << ',';
        json << '"' << targets[i].text << '"';
    }
    json << "]}";
    return json.str();
}

bool await_phase(char expected) {
    HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
    if (GetFileType(input) != FILE_TYPE_PIPE) throw std::invalid_argument("phase control requires a pipe");
    const auto deadline = Clock::now() + std::chrono::minutes(2);
    while (!cancelled && Clock::now() < deadline) {
        DWORD available{};
        if (!PeekNamedPipe(input, nullptr, 0, nullptr, &available, nullptr)) break;
        if (available) {
            char command{};
            DWORD count{};
            return ReadFile(input, &command, 1, &count, nullptr) && count == 1 && command == expected;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
    return false;
}

void measure(Queue& queue, std::atomic_bool& incomplete, std::atomic_bool& observed, const Target& target,
             const std::string& id, unsigned attempts, unsigned hops, unsigned timeout,
             const Options& options, const std::string& phase, const std::atomic_bool* window = nullptr,
             const std::atomic_bool& stop_flag = cancelled, bool console = true) {
    auto active = [&]{return !stop_flag && (!window || window->load());};
    std::optional<Probe> probe;
    if (options.protocol != "tcp") probe.emplace(target);
    for (unsigned attempt = 1; attempt <= attempts && active(); ++attempt) {
        for (std::string_view protocol : {"icmp", "tcp"}) {
            if (options.protocol != "both" && protocol != options.protocol) continue;
            for (unsigned ttl = 1; ttl <= hops && active(); ++ttl) {
                auto start = Clock::now();
                auto timestamp = utc_now();
                auto reply = protocol == "tcp" ? tcp_probe(target, ttl, timeout) : probe->send(ttl, timeout);
                if (window && !window->load()) return;
                {
                    std::lock_guard lock(output);
                    std::ostringstream sample;
                    sample << "{\"schema_version\":1,\"session_id\":\"" << id
                        << "\",\"timestamp\":\"" << timestamp << "\",\"target\":\"" << target.text
                        << "\",\"family\":" << (target.ipv6() ? 6 : 4)
                        << ",\"protocol\":\"" << protocol << "\""
                        << (protocol == "tcp" ? ",\"tcp_port\":443" : "")
                        << ",\"phase\":\"" << phase << "\",\"attempt\":" << attempt
                        << ",\"ttl\":" << ttl << ",\"status\":\"" << reply.status
                        << "\",\"native_code\":" << reply.code << ",\"responder\":";
                    if (reply.responder.empty()) sample << "null,\"rtt_ms\":null";
                    else sample << '"' << reply.responder << "\",\"rtt_ms\":" << reply.rtt_ms;
                    sample << "}";
                    auto record = sample.str();
                    queue.append(id, record);
                    if (console) {
                        std::cout << record << std::endl;
                        if (!std::cout) throw std::runtime_error("sample output failed");
                    }
                }
                if (reply.status == "unavailable") incomplete = true;
                else observed = true;
                const auto due = start + std::chrono::milliseconds(options.interval_ms);
                while (active() && Clock::now() < due)
                    std::this_thread::sleep_until(std::min(due, Clock::now() + std::chrono::milliseconds(50)));
                if (reply.status == "unavailable" || reply.status == "tcp_connected" || reply.status == "tcp_refused") break;
                if ((reply.status == "echo_reply" && reply.responder == target.text) || reply.status == "unreachable") break;
            }
        }
    }
}

unsigned long long ticks(FILETIME time) {
    return (static_cast<unsigned long long>(time.dwHighDateTime) << 32) | time.dwLowDateTime;
}

void resources(Clock::time_point start) {
    FILETIME created{}, exited{}, kernel{}, user{};
    PROCESS_MEMORY_COUNTERS memory{};
    if (!GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user) ||
        !GetProcessMemoryInfo(GetCurrentProcess(), &memory, sizeof memory))
        throw std::runtime_error("resource counters unavailable");
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - start).count();
    std::cerr << "{\"elapsed_ms\":" << elapsed << ",\"cpu_ms\":" << (ticks(kernel) + ticks(user)) / 10000.0
        << ",\"peak_working_set_bytes\":" << memory.PeakWorkingSetSize
        << ",\"cancelled\":" << (cancelled ? "true" : "false") << "}\n";
}
}

static void sync_configured(Queue& queue) {
    if (environment(L"VIPNET_API_ORIGIN").empty() || environment(L"VIPNET_TOKEN").empty()) return;
    try {
        if (queue.sync(false)) std::cerr << "Pending SQLite queue; use --status\n";
    } catch (const std::exception& e) { std::cerr << "Pending SQLite queue: " << e.what() << '\n'; }
}

Json run_desktop_test(const std::atomic_bool& cancel, const std::function<void(const std::string&)>& progress, LiveTraffic& live) {
    WSADATA winsock{};
    if (WSAStartup(MAKEWORD(2, 2), &winsock)) throw std::runtime_error("winsock_unavailable");
    struct Cleanup { ~Cleanup(){ WSACleanup(); } } cleanup;
    Queue queue;
    const auto id = session_id();
    auto device = Json::parse(queue.begin(id, {}));
    bool sealed = false;
    try {
        auto inventory = Json::parse(queue.save_inventory(id)).at("inventory");
        std::atomic_bool incomplete{}, observed{};
        std::exception_ptr error;
        auto trace = [&](const Target& target, const std::string& phase, const std::atomic_bool& window) {
            try {
                progress(phase);
                measure(queue, incomplete, observed, target, id, 5, 8, 200, Options{}, phase, &window, cancel, false);
            } catch (...) { error = std::current_exception(); }
        };
        std::string observed_ip;
        auto report = measure_throughput(queue, id, cancel, trace, &observed_ip, &live);
        Json samples = Json::array();
        for (const auto& raw : queue.recorded_samples(id)) samples.push_back(Json::parse(raw));
        if (error) std::rethrow_exception(error);
        queue.seal(id, cancel ? "cancelled" : report["error"].is_null() && !incomplete ? "completed" : "partial");
        sealed = true;
        progress("sync");
        bool delivered = false;
        try { delivered = queue.sync(false) == 0; } catch (const std::exception&) { }
        return {{"device",std::move(device)},{"observed_ip",observed_ip.empty()?Json(nullptr):Json(observed_ip)},
                {"mtr_samples",std::move(samples)},{"version","0.5.3"},{"throughput",std::move(report)},{"inventory",std::move(inventory)},{"synchronized",delivered}};
    } catch (...) {
        if (!sealed) queue.seal(id, "partial");
        throw;
    }
}

int diagnostics_main(int argc, char** argv) {
    if (argc == 2 || argc == 3) {
        try {
            std::string_view cmd(argv[1]);
            if (cmd == "--version" && argc == 2) { std::cout << "0.5.3\n"; return 0; }
            if (cmd == "--status" && argc == 2) { Queue().status(); return 0; }
            if (cmd == "--sync" && argc == 3 && std::string_view(argv[2]) == "--retry-blocked")
                return Queue().sync(false, true);
            if (cmd == "--sync" && (argc == 2 || std::string_view(argv[2]) == "--wait"))
                return Queue().sync(argc == 3);
        } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
    }
    const bool inventory_only = argc == 2 && std::string_view(argv[1]) == "--inventory";
    const bool throughput_only = argc == 2 && std::string_view(argv[1]) == "--throughput";
    if (argc < 5 && !inventory_only && !throughput_only) {
        std::cerr << "vipnet-mtr --throughput | --inventory | --status | --sync | --version\n";
        std::cerr << "vipnet-mtr ATTEMPTS(1..20) HOPS(1..32) TIMEOUT_MS(100..2000) IP [SECOND_IP] [--protocol icmp|tcp|both] [--interval-ms N] [--phase-control] [--inventory]\n";
        return 2;
    }
    auto start = Clock::now();
    WSADATA winsock{};
    if (WSAStartup(MAKEWORD(2, 2), &winsock)) return 1;
    int result = 0;
    try {
        if (throughput_only) {
            if (!SetConsoleCtrlHandler(stop, TRUE)) throw std::runtime_error("control handler unavailable");
            Queue queue;
            auto id = session_id();
            queue.begin(id, {});
            std::atomic_bool incomplete{}, observed{};
            const Options options{};
            std::exception_ptr mtr_error;
            auto capture = [&](const Target& target, const std::string& phase, const std::atomic_bool& window) {
                try {measure(queue, incomplete, observed, target, id, 5, 8, 200, options, phase, &window);}
                catch (...) {mtr_error = std::current_exception();}
            };
            try {
                auto report = measure_throughput(queue, id, cancelled, capture);
                if (mtr_error) std::rethrow_exception(mtr_error);
                bool complete = report["error"].is_null();
                queue.seal(id, cancelled ? "cancelled" : complete && !incomplete ? "completed" : "partial");
                std::cout << report.dump() << std::endl;
                resources(start);
                if (!cancelled) sync_configured(queue);
                result = cancelled ? 130 : complete ? 0 : 1;
            } catch (...) {queue.seal(id, "partial"); throw;}
            WSACleanup();
            return result;
        }
        if (inventory_only) {
            if (!SetConsoleCtrlHandler(stop, TRUE)) throw std::runtime_error("control handler unavailable");
            Queue queue;
            auto id = session_id();
            queue.begin(id, {});
            try {
                const auto opening = queue.save_inventory(id);
                queue.seal(id, cancelled ? "cancelled" : "completed");
                std::cout << opening << std::endl;
            } catch (...) {
                queue.seal(id, "partial");
                throw;
            }
            if (!cancelled) sync_configured(queue);
            WSACleanup();
            return cancelled ? 130 : 0;
        }
        auto attempts = bounded(argv[1], 1, 20);
        auto hops = bounded(argv[2], 1, 32);
        auto timeout = bounded(argv[3], 100, 2000);
        std::vector<Target> targets{parse_target(argv[4])};
        Options options;
        bool include_inventory = false;
        int pos = 5;
        if (pos < argc && !std::string_view(argv[pos]).starts_with("--")) {
            auto second = parse_target(argv[pos++]);
            if (second.text == targets.front().text) throw std::invalid_argument("duplicate target");
            targets.push_back(second);
        }
        while (pos < argc) {
            std::string_view flag(argv[pos++]);
            if (flag == "--inventory") { include_inventory = true; continue; }
            if (flag == "--phase-control") { options.phased = true; continue; }
            if (pos == argc) throw std::invalid_argument("option requires a value");
            std::string value(argv[pos++]);
            if (flag == "--protocol" && (value == "icmp" || value == "tcp" || value == "both"))
                options.protocol = value;
            else if (flag == "--interval-ms") options.interval_ms = bounded(value.c_str(), 100, 5000);
            else throw std::invalid_argument("invalid measurement option");
        }
        if (options.phased && GetFileType(GetStdHandle(STD_INPUT_HANDLE)) != FILE_TYPE_PIPE)
            throw std::invalid_argument("phase control requires a pipe");
        auto id = session_id();
        if (!SetConsoleCtrlHandler(stop, TRUE)) throw std::runtime_error("control handler unavailable");
        Queue queue;
        queue.begin(id, measurement_parameters(options, targets, attempts, hops, timeout));
        if (include_inventory) {
            try { queue.save_inventory(id); }
            catch (...) { queue.seal(id,"partial"); throw; }
        }
        std::atomic_bool failed{};
        std::atomic_bool incomplete{}, observed{};
        bool controller_error = false;
        const std::array<std::pair<char, std::string>, 4> phases{{
            {'B',"baseline"}, {'D',"download"}, {'U',"upload"}, {'R',"recovery"}}};
        for (const auto& [command, phase] : phases) {
            if (cancelled || failed || (!options.phased && command != 'B')) break;
            if (options.phased && !await_phase(command)) {
                controller_error = !cancelled;
                incomplete = true;
                if (controller_error) std::cerr << "{\"error\":\"phase_signal_missing_or_invalid\"}\n";
                break;
            }
            {
                std::vector<std::jthread> jobs;
                for (auto& target : targets) {
                    jobs.emplace_back([&, target] {
                        try { measure(queue, incomplete, observed, target, id, attempts, hops, timeout, options, phase); }
                        catch (const std::exception& e) {
                            failed = true;
                            cancelled = true;
                            std::lock_guard lock(output);
                            std::cerr << e.what() << '\n';
                        }
                    });
                }
            }
            if (options.phased)
                std::cerr << "{\"phase_finished\":\"" << phase << "\"}" << std::endl;
        }
        const char* state = "completed";
        if (failed) state = "failed";
        else if (cancelled) state = "cancelled";
        else if (incomplete) state = observed ? "partial" : "failed";
        queue.seal(id, state);
        resources(start);
        result = (failed || controller_error) ? 1 : (cancelled ? 130 : 0);
        if (!cancelled) sync_configured(queue);
    } catch (const std::exception& e) {
        std::cerr << e.what() << '\n';
        result = 1;
    }
    WSACleanup();
    return result;
}
