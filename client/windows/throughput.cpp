#include "throughput.hpp"
#include "queue.hpp"
#include <winhttp.h>
#include <bcrypt.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <thread>

namespace {
using Clock = std::chrono::steady_clock;
using namespace std::chrono_literals;
using Handle = std::unique_ptr<void, decltype(&WinHttpCloseHandle)>;

void check(bool ok) {
    if (!ok) throw std::runtime_error("winhttp_" + std::to_string(GetLastError()));
}

void require(bool ok, const char* reason) {
    if (!ok) throw std::runtime_error(reason);
}

Handle handle(HINTERNET raw) {
    check(raw != nullptr);
    return {raw, WinHttpCloseHandle};
}

std::wstring widen(const std::string& value) { return {value.begin(), value.end()}; }

double ms(Clock::time_point start) {
    return std::chrono::duration<double, std::milli>(Clock::now() - start).count();
}

std::string endpoint_ip(const SOCKADDR_STORAGE& endpoint) {
    char text[INET6_ADDRSTRLEN]{};
    auto family = endpoint.ss_family;
    if (family != AF_INET && family != AF_INET6) return {};
    const void* addr = family == AF_INET ?
        static_cast<const void*>(&reinterpret_cast<const sockaddr_in*>(&endpoint)->sin_addr) :
        static_cast<const void*>(&reinterpret_cast<const sockaddr_in6*>(&endpoint)->sin6_addr);
    return InetNtopA(family, addr, text, sizeof(text)) ? text : "";
}

class Channel {
    Handle session_, connection_;
    std::wstring base_;
public:
    std::string peer;
    Channel(const std::string& id, const std::wstring& origin)
        : session_(handle(WinHttpOpen(L"VIP-NET transfer/0.7.1", WINHTTP_ACCESS_TYPE_NO_PROXY, nullptr, nullptr, 0))),
          connection_(nullptr, WinHttpCloseHandle), base_(L"/measure/v1/runs/" + widen(id)) {
        URL_COMPONENTS url{};
        url.dwStructSize = sizeof(url);
        url.dwHostNameLength = url.dwUrlPathLength = url.dwExtraInfoLength =
            url.dwUserNameLength = url.dwPasswordLength = DWORD(-1);
        require(!origin.empty() && WinHttpCrackUrl(origin.c_str(), 0, 0, &url) &&
                url.nScheme == INTERNET_SCHEME_HTTPS && url.dwHostNameLength &&
                !url.dwUserNameLength && !url.dwPasswordLength && !url.dwExtraInfoLength &&
                (!url.dwUrlPathLength || std::wstring_view(url.lpszUrlPath, url.dwUrlPathLength) == L"/"),
                "node_https_origin_required");
        std::wstring host(url.lpszHostName, url.dwHostNameLength);
        check(WinHttpSetTimeouts(session_.get(), 3000, 3000, 4000, 4000));
        connection_ = handle(WinHttpConnect(session_.get(), host.c_str(), url.nPort, 0));
    }

    Handle send(const wchar_t* verb, const wchar_t* suffix, const std::wstring& secret, DWORD size = 0,
                const std::wstring& absolute = {}) {
        const bool public_request = absolute == L"/api/v1/portal/clients" || (absolute == L"/api/v1/portal/game-profiles" && std::wstring_view(verb)==L"GET");
        require(public_request || (secret.size() >= 32 && secret.size() <= 256 &&
                std::all_of(secret.begin(), secret.end(), [](wchar_t c){return c >= 33 && c <= 126;})),
                "node_credential_required");
        auto path = absolute.empty() ? base_ + suffix : absolute;
        auto req = handle(WinHttpOpenRequest(connection_.get(), verb, path.c_str(), L"HTTP/1.1", nullptr, nullptr,
                                             WINHTTP_FLAG_SECURE | WINHTTP_FLAG_REFRESH));
        DWORD policy = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
        check(WinHttpSetOption(req.get(), WINHTTP_OPTION_REDIRECT_POLICY, &policy, sizeof(policy)));
        DWORD disabled = WINHTTP_DISABLE_COOKIES | WINHTTP_DISABLE_AUTHENTICATION;
        check(WinHttpSetOption(req.get(), WINHTTP_OPTION_DISABLE_FEATURE, &disabled, sizeof(disabled)));
        std::wstring headers = L"Accept-Encoding: identity\r\n";
        if (!public_request) headers += L"Authorization: Bearer " + secret + L"\r\n";
        if (size) headers += L"Content-Type: application/octet-stream\r\n";
        check(WinHttpSendRequest(req.get(), headers.c_str(), DWORD(-1), nullptr, 0, size, 0));
        return req;
    }

    void receive(HINTERNET req, DWORD wanted, Json* local_ip = nullptr) {
        check(WinHttpReceiveResponse(req, nullptr));
        DWORD status{}, n = sizeof(status);
        check(WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, nullptr, &status, &n, nullptr));
        if (status != wanted) throw std::runtime_error("node_http_" + std::to_string(status));
        WINHTTP_CONNECTION_INFO info{};
        info.cbSize = sizeof(info);
        DWORD size = sizeof(info);
        check(WinHttpQueryOption(req, WINHTTP_OPTION_CONNECTION_INFO, &info, &size));
        if (local_ip) {
            const auto local = endpoint_ip(info.LocalAddress);
            *local_ip = local.empty() ? unavailable("local_endpoint_unknown") : available(local);
        }
        auto address = endpoint_ip(info.RemoteAddress);
        require(!address.empty(), "peer_address_unavailable");
        if (peer.empty()) peer = address;
        require(address == peer, "node_address_changed");
    }

    static Json json(HINTERNET req, size_t limit=8192) {
        std::array<char, 2048> bytes{};
        std::string body;
        DWORD n{};
        do {
            check(WinHttpReadData(req, bytes.data(), static_cast<DWORD>(bytes.size()), &n));
            require(body.size()+n <= limit, "node_reply_too_large");
            body.append(bytes.data(), n);
        } while (n);
        auto parsed = Json::parse(body, nullptr, false);
        require(parsed.is_object(), "invalid_node_reply");
        return parsed;
    }
};

struct Progress {
    std::atomic<DWORD> bytes{};
    std::atomic<unsigned long long>* live_counter{};
    void record(DWORD amount) {
        bytes.fetch_add(amount, std::memory_order_relaxed);
        if (live_counter) live_counter->fetch_add(amount, std::memory_order_relaxed);
    }
    std::atomic_bool loading{}, done{};
};

Json empty_transfer() {
    return {{"status","unavailable"},{"reason","not_started"},{"client_bytes",0},{"node_bytes",nullptr},
            {"duration_ms",nullptr},{"node_duration_ms",nullptr},{"started_at",nullptr},{"ended_at",nullptr}};
}

void transfer(Channel& bulk, const std::wstring& ticket, bool upload, DWORD size, unsigned rate,
              Clock::time_point deadline, const std::atomic_bool& cancel, Progress& progress, Json& result) {
    const auto start = Clock::now();
    result["started_at"] = utc_now();
    auto keep = [&] {
        require(!cancel, "cancelled");
        require(Clock::now() < deadline, "deadline_exceeded");
    };
    try {
        std::array<unsigned char,32768> buffer{};
        if (upload) require(BCryptGenRandom(nullptr, buffer.data(), static_cast<ULONG>(buffer.size()),
                                            BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0, "random_payload_unavailable");
        auto req = bulk.send(upload ? L"POST" : L"GET", upload ? L"/upload" : L"/download", ticket, upload ? size : 0);
        if (!upload) bulk.receive(req.get(), 200);
        auto body_start = Clock::now();
        DWORD count = 0;
        while (count < size) {
            keep();
            auto block = std::min<DWORD>(size-count, static_cast<DWORD>(buffer.size()));
            DWORD n{};
            if (upload) {
                auto due = body_start + std::chrono::duration<double>((count + block) * 8.0 / rate);
                while (Clock::now() < due) { keep(); std::this_thread::sleep_for(2ms); }
                check(WinHttpWriteData(req.get(), buffer.data(), block, &n));
            } else {
                check(WinHttpReadData(req.get(), buffer.data(), block, &n));
            }
            require(n != 0, "short_transfer");
            count += n;
            progress.record(n);
            progress.loading = count < size;
        }
        Json node;
        if (upload) {
            // WinHTTP may finish writing while a slow link still drains buffered payload.
            // The node acknowledges only after consuming the full body.
            keep();
            auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now()).count();
            int ack_timeout = static_cast<int>(std::clamp<long long>(remaining, 1, 30000));
            check(WinHttpSetTimeouts(req.get(), 3000, 3000, 4000, ack_timeout));
            bulk.receive(req.get(), 200);
            result["duration_ms"] = ms(start);
            node = Channel::json(req.get());
        } else {
            DWORD n{};
            check(WinHttpReadData(req.get(), buffer.data(), 1, &n));
            require(n == 0, "unexpected_extra_bytes");
            result["duration_ms"] = ms(start);
            auto status = bulk.send(L"GET", L"/status", ticket);
            bulk.receive(status.get(), 200);
            node = Channel::json(status.get()).at("download");
        }
        result["node_bytes"] = node.at("bytes").get<DWORD>();
        result["node_duration_ms"] = node.at("duration_ms").get<double>();
        require(node.at("complete") == true && result["node_bytes"] == count, "node_count_mismatch");
        result["reason"] = nullptr;
        result["status"] = "ok";
    } catch (const std::exception& e) {
        result["status"] = progress.bytes ? "partial" : "unavailable";
        result["reason"] = e.what();
    }
    progress.loading = false;
    result["client_bytes"] = progress.bytes.load();
    if (result["duration_ms"].is_null()) result["duration_ms"] = ms(start);
    result["ended_at"] = utc_now();
    progress.done = true;
}
// Each upload request fits the staging proxy's one-MiB body limit. Grow blocks on faster links.
void windowed_transfer(const std::string& id, const std::wstring& origin, Channel& control,
                       const std::wstring& ticket, const std::string& direction, const Json& profile,
                       Clock::time_point deadline, const std::atomic_bool& cancel, Progress& progress, Json& result) {
    const auto start = Clock::now();
    const auto end = start + std::chrono::milliseconds(profile.at("window_ms").get<int>());
    const DWORD budget = profile.at("bytes").get<DWORD>();
    const unsigned rate = profile.at("rate_bps").get<unsigned>();
    const bool upload = direction == "upload";
    const auto prefix = L"/blocks/" + widen(direction) + L"/";
    std::mutex lock;
    DWORD allocated = 0, next_index = 0;
    std::atomic_bool failed{};
    std::exception_ptr exception;
    result["started_at"] = utc_now();
    progress.loading = true;
    try {
        std::vector<std::jthread> workers;
        auto lane = [&] {
            try {
                Channel channel(id, origin);
                channel.peer = control.peer;
                std::vector<unsigned char> buffer(1 << 20);
                if (upload) require(BCryptGenRandom(nullptr, buffer.data(), static_cast<ULONG>(buffer.size()),
                    BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0, "random_payload_unavailable");
                DWORD desired = 65536;
                for (;;) {
                    DWORD index, n, total;
                    {
                        std::lock_guard guard(lock);
                        if (cancel || failed || Clock::now() >= end || budget - allocated < 65536) break;
                        index = next_index++;
                        n = std::min(desired, budget - allocated);
                        allocated += n;
                        total = allocated;
                    }
                    auto chunk_start = Clock::now();
                    if (upload) {
                        auto due = start + std::chrono::duration<double>(total * 8.0 / rate);
                        while (Clock::now() < due) {
                            require(!cancel && !failed && Clock::now()<deadline, "transfer_interrupted");
                            std::this_thread::sleep_for(1ms);
                        }
                    }
                    auto path = prefix + std::to_wstring(index) + L"?n=" + std::to_wstring(n);
                    auto req = channel.send(upload ? L"POST" : L"GET", path.c_str(), ticket, upload ? n : 0);
                    if (!upload) channel.receive(req.get(), 200);
                    DWORD count = 0;
                    while (count < n) {
                        require(!cancel && !failed && Clock::now()<deadline, "transfer_interrupted");
                        DWORD part{};
                        if (upload) check(WinHttpWriteData(req.get(), buffer.data()+count, n-count, &part));
                        else check(WinHttpReadData(req.get(), buffer.data()+count, n-count, &part));
                        require(part>0, "short_block");
                        progress.record(part);
                        count += part;
                    }
                    if (upload) channel.receive(req.get(), 204);
                    else {
                        DWORD extra{};
                        check(WinHttpReadData(req.get(),buffer.data(),1,&extra));
                        require(extra==0,"unexpected_extra_bytes");
                    }
                    auto elapsed = Clock::now()-chunk_start;
                    if (elapsed < 300ms) desired=std::min<DWORD>(1<<20, desired*2);
                    else if (elapsed > 900ms) desired=std::max<DWORD>(65536, desired/2);
                }
            } catch (...) {
                std::lock_guard guard(lock);
                if (!exception) exception=std::current_exception();
                failed=true;
            }
        };
        for (int i=0; i<profile.at("streams").get<int>(); ++i) workers.emplace_back(lane);
        for (auto& worker : workers) worker.join();
        progress.loading = false;
        if (exception) std::rethrow_exception(exception);
        require(!cancel && Clock::now()<deadline && allocated>0,"transfer_interrupted");
        auto path = L"/commit/"+widen(direction);
        auto req = control.send(L"POST",path.c_str(),ticket);
        control.receive(req.get(),200);
        auto summary=Channel::json(req.get());
        result["node_bytes"]=summary.at("bytes");
        result["node_duration_ms"]=summary.at("duration_ms");
        require(summary.at("complete")==true && result["node_bytes"]==progress.bytes.load(),"node_count_mismatch");
        result["status"]="ok";
        result["reason"]=nullptr;
    } catch (const std::exception& e) {
        result["status"]=progress.bytes ? "partial" : "unavailable";
        result["reason"]=e.what();
    }
    progress.loading=false;
    result["client_bytes"]=progress.bytes.load();
    result["duration_ms"]=ms(start);
    result["ended_at"]=utc_now();
    progress.done=true;
}
} // namespace

Json fetch_game_profiles(const std::wstring& origin) {
    Channel channel("",origin);
    auto request=channel.send(L"GET",L"",{},0,L"/api/v1/portal/game-profiles");
    channel.receive(request.get(),200);
    auto catalog=Channel::json(request.get(),32768);
    if (catalog.value("version",0)!=1 || !catalog.at("profiles").is_array() || catalog.at("profiles").size()>64)
        throw std::runtime_error("invalid_game_catalog");
    return catalog;
}

std::wstring register_desktop_client(const std::wstring& origin) {
    Channel channel("", origin);
    auto request = channel.send(L"POST", L"", {}, 0, L"/api/v1/portal/clients");
    channel.receive(request.get(), 201);
    auto token = Channel::json(request.get()).at("token").get<std::string>();
    require(token.size() >= 32 && token.size() <= 128 &&
        token.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") == token.npos,
        "invalid_client_credential");
    return widen(token);
}

void LiveTraffic::clear() {
    std::lock_guard lock(mutex_);
    received=0; sent=0; profile_bps=0;
    traces_={Json::array(),Json::array()};
}

void LiveTraffic::observe(size_t direction,unsigned long long bytes) {
    std::lock_guard lock(mutex_);
    auto& rows=traces_.at(direction);
    const auto now=std::chrono::steady_clock::now();
    if (rows.empty()) starts_[direction]=now;
    const auto elapsed=std::chrono::duration_cast<std::chrono::milliseconds>(now-starts_[direction]).count();
    if (rows.size()<1024 && (rows.empty() || elapsed>rows.back()[0].get<long long>()))
        rows.push_back({elapsed,bytes});
}

Json LiveTraffic::trace(size_t direction) const {
    std::lock_guard lock(mutex_);
    return traces_.at(direction);
}

Json measure_throughput(Queue& queue, const std::string& id, const std::atomic_bool& cancel, const PhaseMtr& mtr,
                        std::string* observed_ip, LiveTraffic* live) {
    Json doc = {{"schema_version",1},{"session_id",id},{"windows_version",windows_version()},
        {"started_at",utc_now()},{"ended_at",nullptr},{"node_id",nullptr},{"peer",nullptr},{"profile",nullptr},
        {"error","measurement_interrupted"},{"mtr",{{"attempts",5},{"max_ttl",8},{"timeout_ms",200},{"interval_ms",100},{"protocol","icmp"}}},{"phases",Json::object()},
        {"transfers",{{"download",empty_transfer()},{"upload",empty_transfer()}}}};
    const std::array<std::string,4> phases{"baseline","download","upload","recovery"};
    for (auto& name : phases) doc["phases"][name] = Json::array();
    if (doc["windows_version"] == "") doc["windows_version"] = "unavailable:RtlGetVersion";
    doc["reservation_local_ip"] = unavailable("no_reservation");
    auto save = [&]{queue.save_throughput(id, doc.dump());};
    save();
    try {
        auto origin = environment(L"VIPNET_NODE_ORIGIN");
        Channel control(id, origin), bulk(id, origin);
        const bool portal = environment(L"VIPNET_PORTAL_RESERVATION") == L"1";
        auto reserve = control.send(L"POST", L"", environment(portal ? L"VIPNET_TOKEN" : L"VIPNET_NODE_TOKEN"), 0,
                                    portal ? L"/api/v1/portal/runs/" + widen(id) + (live && !live->capacity ? L"?profile=legacy" : L"?profile=capacity") : L"");
        control.receive(reserve.get(), 201, &doc["reservation_local_ip"]);
        auto offer = Channel::json(reserve.get());
        std::string canonical = id;
        std::transform(canonical.begin(), canonical.end(), canonical.begin(), [](char c){return char(std::tolower(c));});
        require(offer.at("session_id") == canonical, "node_session_mismatch");
        const bool share_trace=portal && live && offer.value("accepts_desktop_trace",false);
        if (share_trace) doc["desktop_trace"]={{"session_id",id},{"download",Json::array()},{"upload",Json::array()}};
        auto ticket = widen(offer.at("ticket").get<std::string>());
        auto profile = offer.at("profile");
        if (observed_ip && offer.contains("observed_ip")) *observed_ip=offer.at("observed_ip").get<std::string>();
        bool windowed = profile.value("mode",std::string{})=="windowed";
        auto size = profile.at("bytes").get<int64_t>(), rate = profile.at("rate_bps").get<int64_t>();
        auto seconds = profile.at("deadline_s").get<int64_t>();
        require(size >= 65536 && size <= (windowed?512:64)*1024*1024 && rate >= 262144 && rate <= (windowed?1000000000:100000000) &&
                seconds >= 10 && seconds <= 180, "unsafe_node_profile");
        if (windowed) require(profile.at("window_ms")>=2000 && profile.at("window_ms")<=10000 &&
            profile.at("streams")>=1 && profile.at("streams")<=4,"unsafe_node_profile");
        auto node = offer.at("node_id").get<std::string>();
        require(!node.empty() && node.size() <= 64, "invalid_node_id");
        auto target = parse_target(control.peer.c_str());
        bulk.peer = control.peer;
        doc["node_id"] = node; doc["profile"] = profile; doc["peer"] = target.text;
        if (live) live->profile_bps = static_cast<unsigned long long>(rate);
        auto deadline = Clock::now() + std::chrono::seconds(seconds);
        save();
        for (const auto& phase : phases) {
            if (cancel || Clock::now() >= deadline) break;
            bool loaded = phase == "download" || phase == "upload";
            Progress progress;
            if (loaded && live) progress.live_counter = phase == "upload" ? &live->sent : &live->received;
            Json result = empty_transfer();
            std::jthread load;
            if (loaded) {
                if (live) live->observe(phase=="upload",0);
                load = std::jthread([&]{
                    if (windowed) windowed_transfer(id, origin, bulk, ticket, phase, profile, deadline, cancel, progress, result);
                    else transfer(bulk, ticket, phase=="upload", static_cast<DWORD>(size),
                        static_cast<unsigned>(rate), deadline, cancel, progress, result);
                });
                while (!progress.loading && !progress.done && !cancel) std::this_thread::sleep_for(5ms);
            }
            auto quiet_end = Clock::now() + 1800ms;
            auto in_window = [&] {return !cancel && Clock::now() < deadline &&
                                          (loaded ? progress.loading.load() : Clock::now() < quiet_end);};
            std::atomic_bool window{in_window()};
            auto& samples = doc["phases"][phase];
            {
                std::jthread trace([&]{ if (window) mtr(target, phase, loaded ? progress.loading : window); });
                struct Stop {std::atomic_bool& flag; ~Stop(){flag=false;}} stop{window};
                while (in_window()) {
                    if (samples.size() >= 100) {std::this_thread::sleep_for(50ms); continue;}
                    if (loaded && live) live->observe(phase=="upload",progress.bytes.load());
                    auto start = Clock::now();
                    Json sample = {{"at",utc_now()},{"ms",nullptr},{"error",nullptr}};
                    try {
                        auto ping = control.send(L"HEAD", L"/latency", ticket);
                        control.receive(ping.get(), 204);
                        sample["ms"] = ms(start);
                    } catch (const std::exception& e) {sample["error"] = e.what();}
                    if (in_window()) samples.push_back(std::move(sample));
                    if (loaded) {
                        auto& current = doc["transfers"][phase];
                        current["client_bytes"] = progress.bytes.load();
                        current["status"] = "partial"; current["reason"] = "measurement_interrupted";
                    }
                    save();
                    auto next = start + 150ms;
                    while (in_window() && Clock::now() < next) std::this_thread::sleep_for(5ms);
                }
            }
            if (loaded) {
                load.join();
                if (live) live->observe(phase=="upload",progress.bytes.load());
                doc["transfers"][phase] = result;
                if (share_trace) doc["desktop_trace"][phase]=live->trace(phase=="upload");
            }
            save();
        }
        auto close = control.send(L"POST", L"/finish", ticket);
        control.receive(close.get(), 204);
        doc["error"] = nullptr;
        if (cancel) doc["error"] = "cancelled";
        else if (Clock::now() >= deadline) doc["error"] = "deadline_exceeded";
        else if (doc["transfers"]["download"]["status"] != "ok" || doc["transfers"]["upload"]["status"] != "ok")
            doc["error"] = "incomplete_transfer";
    } catch (const Json::exception&) {doc["error"] = "invalid_node_document";}
      catch (const std::exception& e) {doc["error"] = e.what();}
    if (cancel) doc["error"] = "cancelled";
    doc["ended_at"] = utc_now();
    save();
    return doc;
}
