#include "throughput.hpp"
#include "queue.hpp"
#include "game_relay.hpp"
#include <filesystem>
#include <iostream>

int main() {
    auto path=std::filesystem::temp_directory_path()/(L"NetDiagnostics-route-"+std::to_wstring(GetCurrentProcessId())+L"-"+std::to_wstring(GetTickCount64()));
    if(!std::filesystem::create_directory(path))return 1;
    struct Cleanup {std::filesystem::path path;~Cleanup(){std::error_code ignored;std::filesystem::remove_all(path,ignored);}} cleanup{path};
    SetEnvironmentVariableW(L"VIPNET_QUEUE_DIR",path.c_str());
    SetEnvironmentVariableW(L"VIPNET_TOKEN",nullptr);
    SetEnvironmentVariableW(L"VIPNET_API_ORIGIN",nullptr);
    using namespace std::chrono;
    sys_seconds now=sys_days{year{2026}/November/25}+hours{12};
    std::string marker=",1 [FLog::Network] UDMUX Address = 192.0.2.10, Port = 54000 | RCC Server Address = 198.51.100.2";
    auto relay=roblox_relay_line("2026-11-25T11:20:00.000Z"+marker,now);
    if(!relay || relay->host!="192.0.2.10" || public_game_target(parse_target(relay->host.c_str())) ||
       roblox_relay_line("2026-11-23T11:20:00.000Z"+marker,now) ||
       roblox_relay_line("2026-11-26T11:20:00.000Z"+marker,now) ||
       roblox_relay_line("2026-11-25T11:20:00.000Z,1 RCC Server Address = 198.51.100.2",now)) return 1;
    std::string connect="0002.000| ALWAYS| CONN| Connecting to address (203.0.113.9) port (7170)\n";
    if(league_match_address(connect) ||
       league_match_address(connect+"0002.800| ALWAYS| CONN| Game Info Received: Initial Connection\n")!="203.0.113.9") return 1;
    for(const char* host:{"192.0.2.1","2001:db8::1","::1","127.0.0.1","100.64.0.1","fd00::123","169.254.2.3"})
        if(public_game_target(parse_target(host))) return 1;
    RouteRequest denied;denied.host="127.0.0.1";denied.protocol="icmp";denied.purpose="gaming";denied.target_kind="session_relay";
    try {run_route(denied,std::atomic_bool(false),{});return 1;} catch(const std::invalid_argument&) {}
    for(bool direct:{false,true}){
        std::atomic_bool stopped{};
        RouteRequest r;r.purpose=direct?"gaming":"mtr";r.host=direct?"::1":"127.0.0.1";r.profile="Test";r.protocol="icmp";
        r.direct=direct;r.ttl=direct?64:4;r.attempts=3;r.family=direct?6:4;
        Json seen=Json::array();
        auto doc=run_route(r,stopped,[&](const Json& sample){seen.push_back(sample);if(!direct && seen.size()==2)stopped=true;});
        if(doc.at("state")!=(direct?"completed":"cancelled") || doc.at("synchronized")!=false ||
           doc.at("mtr_samples")!=seen || seen.size()!=(direct?3u:2u))return 1;
        for(const auto& s:seen) if(s.at("session_id")!=doc.at("session_id") || s.at("target")!=r.host ||
                                   s.at("family")!=r.family || s.at("status")!="echo_reply")return 1;
    }
    std::cout<<"Loopback IPv4 MTR cancellation and IPv6 gaming echo retained all samples offline\n";
}
