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
    require(empty.metrics[0].value==L"—","absent speed shown as zero");
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
    require(legacy.recorded && legacy.metrics[0].value==L"1" && legacy.lines[0].empty(),"old report");
    require(legacy.metrics[2].value==L"—" && legacy.checks[7].tone==Tone::neutral,"fabricated result");
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
    require(read(report).checks[9].tone==Tone::warning,"load increase");
    std::cout<<"Summary metrics, legacy reader, trace integrity, partial and unavailable states passed\n";
}
