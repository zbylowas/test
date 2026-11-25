#include "throughput.hpp"
#include "queue.hpp"
#include <filesystem>
#include <iostream>

int main() {
    auto path=std::filesystem::temp_directory_path()/(L"NetDiagnostics-route-"+std::to_wstring(GetCurrentProcessId())+L"-"+std::to_wstring(GetTickCount64()));
    if(!std::filesystem::create_directory(path))return 1;
    struct Cleanup {std::filesystem::path path;~Cleanup(){std::error_code ignored;std::filesystem::remove_all(path,ignored);}} cleanup{path};
    SetEnvironmentVariableW(L"VIPNET_QUEUE_DIR",path.c_str());
    SetEnvironmentVariableW(L"VIPNET_TOKEN",nullptr);
    SetEnvironmentVariableW(L"VIPNET_API_ORIGIN",nullptr);
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
