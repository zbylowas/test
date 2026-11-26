#include "summary_view.hpp"
#include <cmath>
#include <iostream>
#include <stdexcept>

namespace {
void require(bool value,const char* reason) {if(!value) throw std::runtime_error(reason);}
void layout_at_dpi() {
    INITCOMMONCONTROLSEX common{sizeof common,ICC_WIN95_CLASSES};
    InitCommonControlsEx(&common);
    auto parent=CreateWindowW(L"STATIC",L"Layout check",WS_OVERLAPPEDWINDOW,0,0,1366,768,nullptr,nullptr,GetModuleHandleW(nullptr),nullptr);
    require(parent!=nullptr,"test window");
    summary::View view;
    view.create(parent,L"https://example.invalid",L"NetDiagnostics");
    auto bounds=[&](int id){RECT r{};GetWindowRect(GetDlgItem(parent,id),&r);return r;};
    for (auto dpi:{96u,120u,144u,192u}) {
        view.scale(dpi);
        view.scroll(SB_PAGEDOWN);
        require(bounds(summary::finding_id).bottom<=bounds(111).top,"scroll to last row");
        view.scroll(SB_PAGEUP);
        require(bounds(summary::metric_id).right<=bounds(summary::metric_id+1).left,"transfer cards overlap");
        require(bounds(summary::metric_id+1).bottom<=bounds(summary::metric_id+2).top,"metric rows overlap");
    }
    DestroyWindow(parent);view.destroy();
}

}

int main() {
    using namespace summary;
    layout_at_dpi();
    Json samples=Json::array();
    for(int i=1;i<=4;++i){
        const bool echo=i<=2;
        samples.push_back({{"target","192.0.2.22"},{"family",4},{"protocol","icmp"},{"phase","baseline"},{"attempt",i},{"ttl",4},
            {"status",echo?"echo_reply":i==3?"timeout":"unavailable"},{"responder",echo?Json("192.0.2.22"):Json(nullptr)},{"rtt_ms",echo?Json(i):Json(nullptr)}});
    }
    auto route=route_page(samples);require(route.rows.size()==1,"missing hop");
    auto& hop=route.rows.front();require(hop.cells.size()==16 && hop.cells[5]==L"3" && hop.cells[6]==L"2" && hop.cells[15]==L"1","local error counted as loss");
    require(hop.cells[7]==L"33,3" && hop.cells[8]==L"—" && hop.points.size()==4 && !hop.points.back(),"MTR missing sample");
    auto game=ping_page(samples);require(game.rows[1].cells[1]==L"1 ms" && game.rows[2].cells[1]==L"33,3 %","game jitter/loss");
    samples.back()["family"]=6;samples.back()["target"]="2001:db8::22";require(route_page(samples).rows.size()==2,"mixed IP series");
    auto empty=read(nullptr);
    for(const auto& f:empty.checks) require(f.tone==Tone::neutral,"empty diagnostic classified");
    require(empty.metrics[0].value==L"—" && !empty.speed_mbps[0],"absent speed shown as zero");
    require(empty.checks.size()==9 && empty.checks[check_dns].label==L"DNS","obsolete diagnostic card");
    auto points=rates(Json::array({{0,0},{100,12500},{250,50000}}));
    require(points.size()==2 && std::abs(points[0].mbps-1)<1e-8 && std::abs(points[1].mbps-2)<1e-8,"counter deltas");
    for(auto rows:{Json::array({{0,1},{0,2}}),Json::array({{0,12},{10,9}}),Json::array({{0,nullptr}})})
        require(rates(rows).empty(),"corrupt local series accepted");
    const char* ip="192.0.2.10";
    Json ping={{"status","echo_reply"},{"responder",ip},{"rtt_ms",0}};
    Json timeout={{"status","timeout"}},error={{"status","unavailable"}};
    Json transfer={{"status","ok"},{"client_bytes",125000},{"node_bytes",125000},{"duration_ms",1000}};
    Json t={{"session_id","abed342a-5691-4dad-bcdb-dd43a3828567"},{"error",nullptr},{"profile",{{"bytes",125000}}},
        {"transfers",{{"download",transfer},{"upload",transfer}}},{"phases",Json::object()}};
    Json report={{"throughput",t},{"synchronized",false}};
    auto legacy=read(report);
    require(legacy.recorded && legacy.metrics[0].value==L"1" && legacy.speed_mbps[0]==1 && legacy.lines[0].empty(),"old report");
    require(legacy.metrics[2].value==L"—" && legacy.checks[check_ipv6].tone==Tone::neutral,"fabricated result");
    report["throughput"]["reservation_local_ip"]={{"value",ip}};
    report["observed_ip"]="203.0.113.44";
    Json nic={{"unicast",{{"value",Json::array({{{"ip",ip}},{{"ip","fe80::10%2"}},{{"ip","fd00::10"}},{{"ip","2001:db8::10"}}})}}},
        {"dns",{{"value",Json::array({"192.0.2.53","198.51.100.53","fe80::53","fd00::53","2001:db8::53"})}}},{"model",{{"value","Fixture NIC"}}}};
    report["inventory"]["interfaces"]["value"]=Json::array({nic});
    auto internet=read(report);
    require(internet.checks[check_dns].value==L"192.0.2.53","DNS address missing");
    require(internet.checks[check_ipv4].value==L"203.0.113.44" &&
            internet.checks[check_ipv6].value==L"2001:db8::10","IP addresses not shown");
    auto internet_page=detail_page(5,report,internet);
    require(internet_page.rows[3].cells[1]==L"2001:db8::10" &&
            internet_page.rows[4].cells[0]==L"IPv6 · prywatny (ULA)" &&
            internet_page.rows[5].cells[1]==L"fe80::10%2","IPv6 rows not ordered by scope");
    bool local_ip=false,dns=false,v6_status=false;
    for(const auto& row:internet_page.rows){
        local_ip|=row.cells[0]==L"IPv4 · karta" && row.cells[1]==L"192.0.2.10";
        dns|=row.cells[0]==L"DNS IPv4" && row.cells[1]==L"192.0.2.53";
        require(row.cells[0]!=L"DNS IPv6 · publiczny","local or documentation IPv6 DNS shown publicly");
        require(row.cells[1]!=L"198.51.100.53","second IPv4 DNS displayed");
        v6_status|=row.cells[0]==L"DNS IPv6" && row.cells[1]==L"Nieskonfigurowane";
    }
    require(local_ip && dns && v6_status,"Internet view missing address or IPv6 DNS status");
    auto only_local=report;
    only_local["inventory"]["interfaces"]["value"][0]["unicast"]["value"]=Json::array({{{"ip",ip}},{{"ip","fe80::10%2"}}});
    require(read(only_local).checks[check_ipv6].value==L"Tylko link-local","local IPv6 confused with internet address");
    only_local["inventory"]["interfaces"]["value"].push_back(
        {{"oper_status",1},{"type",6},{"unicast",{{"value",Json::array({{{"ip","2001:db8::12"},{"dad_state",4}}})}}}});
    require(read(only_local).checks[check_ipv6].value==L"2001:db8::12","IPv6 on other active card missing");
    only_local["observed_ip"]="2001:db8::20";
    require(read(only_local).checks[check_ipv6].value==L"2001:db8::20","address observed by HTTPS not prioritized");
    auto& node=report["throughput"]["host_pings"]["node"];
    node={{"target",ip},{"planned",5},{"reason",nullptr},{"samples",{ping,ping,timeout,ping,ping}}};
    auto result=read(report);
    require(result.metrics[2].value==L"0" && result.metrics[3].value==L"0" && result.metrics[4].value==L"20","zero RTT and direct loss");
    node["samples"][2]=error;require(read(report).metrics[4].value==L"—","local failure counted as loss");
    node["samples"]={ping,timeout,ping};require(read(report).metrics[3].value==L"—","jitter spans a break");
    node["reason"]="cancelled";require(read(report).partial,"cancelled ping marked complete");
    report["desktop_trace"]={{"session_id","different"},{"download",{{0,0},{100,100}}}};
    require(read(report).lines[0].empty(),"cross-session trace");
    report["desktop_trace"]["session_id"]=t["session_id"];require(read(report).lines[0].size()==1,"lost trace");
    report["throughput"]["transfers"]["download"]["node_bytes"]=100;
    require(read(report).metrics[0].value==L"—","unconfirmed transfer");
    auto& load=report["throughput"]["phases"];
    Json sample={{"error",nullptr},{"ms",5}};
    for(int i=0;i<5;++i) {load["baseline"].push_back(sample);load["upload"].push_back({{"error",nullptr},{"ms",50}});}
    require(read(report).checks[check_latency].tone==Tone::warning,"load increase");
    std::cout<<"Summary metrics, legacy reader, trace integrity, partial and unavailable states passed\n";
}
