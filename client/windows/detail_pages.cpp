#include "detail_pages.hpp"
#include <algorithm>
#include <cmath>
#include <map>
#include <numeric>
#include <set>
#include <tuple>

namespace summary {
namespace {
std::wstring value(const Json& v) {
    if (v.is_string()) return from_utf8(v.get<std::string>());
    return v.is_number()?number(v.get<double>()):L"Brak odczytu";
}
const Json& reading(const Json& j,const char* key){return field(field(j,key),"value");}
std::wstring phase(const Json& v){
    if(v=="baseline") return L"Spoczynek";
    if(v=="upload") return L"Wysyłanie";
    if(v=="download") return L"Pobieranie";
    return v=="recovery"?L"Po transferze":value(v);
}
double percentile(const std::vector<double>& sorted,double fraction){
    return sorted[static_cast<size_t>(std::ceil(sorted.size()*fraction))-1];
}
void metric(DetailPage& p,std::wstring name,std::wstring result,std::wstring why){
    p.rows.push_back({{std::move(name),std::move(result)},std::move(why),{},{}});
}
void fact(DetailPage& p,const Fact& f,const std::wstring& unit=L""){
    metric(p,f.label,f.value+(f.value==L"—"?L"":unit),f.detail);
}
}
DetailPage ping_page(const Json& samples){
    DetailPage page{L"Opóźnienia do wybranego celu ICMP",{{L"Pomiar",220},{L"Wynik",340}},{}};
    if(!samples.is_array() || samples.empty())return page;
    const auto& first=samples.front();auto target=value(field(first,"target"));
    std::vector<double> ms;std::vector<std::optional<double>> trace;
    size_t timeout=0,errors=0,other=0,pairs=0;double deltas=0;
    std::optional<double> previous;
    for(const auto& s:samples){
        if(field(s,"status")=="echo_reply" && field(s,"target")==field(s,"responder") && field(s,"rtt_ms").is_number()){
            double v=s.at("rtt_ms").get<double>();ms.push_back(v);trace.push_back(v);
            if(previous){deltas+=std::abs(v-*previous);++pairs;}previous=v;
        }else{
            previous.reset();trace.push_back({});
            if(field(s,"status")=="timeout")++timeout;else if(field(s,"status")=="unavailable")++errors;else ++other;
        }
    }
    std::sort(ms.begin(),ms.end());
    metric(page,L"Typowy ping",ms.empty()?L"Brak odpowiedzi":number(percentile(ms,.5))+L" ms",L"Mediana czasu odpowiedzi celu "+target+L". Wykres pokazuje kolejne próby ICMP.");
    page.rows.back().points=std::move(trace);page.rows.back().unit=L"ms";
    metric(page,L"Zmienność pingu",pairs?number(deltas/pairs)+L" ms":L"Za mało odpowiedzi",L"Średnia różnica między czasami dwóch kolejnych odpowiedzi. Pomijamy pary rozdzielone brakiem odpowiedzi.");
    auto sent=samples.size()-errors;
    metric(page,L"Próby bez echa celu",sent?number(100.*(timeout+other)/sent)+L" %":L"Brak wysłanych prób",
        L"Wysłano "+std::to_wstring(sent)+L", cel odpowiedział "+std::to_wstring(ms.size())+L" razy. Przekroczenia czasu: "+std::to_wstring(timeout)+L". Inne odpowiedzi: "+std::to_wstring(other)+L". Błędy lokalne: "+std::to_wstring(errors)+L".");
    metric(page,L"Ping P95",ms.empty()?L"Brak odpowiedzi":number(percentile(ms,.95))+L" ms",L"95% zarejestrowanych odpowiedzi miało czas nie większy od wskazanego.");
    metric(page,L"Adres celu",target,L"Adres wybrany przez system Windows na początku tej sesji.");
    return page;
}
DetailPage route_page(const Json& samples){
    DetailPage p{L"Wybierz skok, aby zobaczyć czasy kolejnych odpowiedzi.",{
        {L"Skok",58},{L"Adres routera",150},{L"Cel",145},{L"Faza",94},{L"Protokół",84},{L"Wysłano",75},{L"Odebrano",82},
        {L"Brak (%)",75},{L"Ostatni",72},{L"Min",62},{L"Średnia",74},{L"Maks.",66},{L"Odch. std.",86},{L"P95",62},{L"P99",62},{L"Błędy API",82}},{}};
    using Key=std::tuple<std::string,int,std::string,std::string,int>;
    std::map<Key,std::vector<const Json*>> groups;
    for(const auto& s:samples) {
        if(!s.is_object() || !field(s,"ttl").is_number_integer())continue;
        groups[{s.value("target",""),s.value("family",0),s.value("protocol",""),s.value("phase",""),s.at("ttl").get<int>()}].push_back(&s);
    }
    for(auto& [key,rows]:groups){
        std::stable_sort(rows.begin(),rows.end(),[](auto a,auto b){return a->at("attempt")<b->at("attempt");});
        const auto& [target,family,proto,ph,ttl]=key;
        std::set<std::wstring> responders;
        std::vector<double> sorted;
        DetailRow row;
        size_t errors=0,miss=0;
        for(auto ptr:rows){
            const auto& s=*ptr;
            const auto& t=field(s,"rtt_ms");
            if(t.is_number()){
                auto ms=t.get<double>();sorted.push_back(ms);row.points.push_back(ms);
                if(field(s,"responder").is_string())responders.insert(value(s.at("responder")));
            }else{row.points.push_back({});if(field(s,"status")=="timeout")++miss;else ++errors;}
        }
        std::wstring routers;
        for(const auto& ip:responders){if(!routers.empty())routers+=L", ";routers+=ip;}
        const size_t sent=rows.size()-errors;
        auto last=row.points.back();
        row.cells={std::to_wstring(ttl),routers.empty()?L"—":routers,from_utf8(target),phase(ph),
            (proto=="tcp"?L"TCP 443":L"ICMP")+std::wstring(family==6?L" v6":L" v4"),std::to_wstring(sent),
            std::to_wstring(sorted.size()),sent?number(100.0*miss/sent):L"—",last?number(*last):L"—"};
        std::sort(sorted.begin(),sorted.end());
        if(sorted.empty())row.cells.insert(row.cells.end(),6,L"—");
        else{
            double mean=std::accumulate(sorted.begin(),sorted.end(),0.)/sorted.size(),variance=0;
            for(double v:sorted)variance+=(v-mean)*(v-mean);
            row.cells.insert(row.cells.end(),{number(sorted.front()),number(mean),number(sorted.back()),
                number(std::sqrt(variance/sorted.size())),number(percentile(sorted,.95)),number(percentile(sorted,.99))});
        }
        row.cells.push_back(std::to_wstring(errors));row.unit=L"ms";
        row.detail=L"Skok "+std::to_wstring(ttl)+L"  ·  "+
            (routers.empty()?L"Adres nieustalony":routers)+L"  ·  Odpowiedzi "+std::to_wstring(sorted.size())+L" z "+std::to_wstring(sent)+
            L". Brak odpowiedzi na tym skoku wymaga porównania z dalszymi skokami i celem.";
        p.rows.push_back(std::move(row));
    }
    return p;
}
DetailPage detail_page(int page,const Json& report,const Snapshot& s){
    DetailPage p{L"Wybierz pozycję, aby odczytać szczegóły pomiaru.",{{L"Pomiar",224},{L"Wynik",340}},{}};
    const auto& t=field(report,"throughput");const auto& inv=field(report,"inventory");
    auto nic=used_adapter(inv,t);
    if(page==1){
        for(int i=0;i<2;++i){
            fact(p,s.metrics[i],L" Mb/s");
            auto& r=p.rows.back();r.unit=L"Mb/s";
            std::vector<double> v;
            for(auto pt:s.lines[i]){r.points.push_back(pt.mbps);v.push_back(pt.mbps);}
            if(!v.empty()){
                std::sort(v.begin(),v.end());r.detail+=L" Próbki chwilowe (Mb/s) · min "+number(v.front())+L" · P10 "+number(percentile(v,.1))+L" · mediana "+number(percentile(v,.5))+L" · maks. "+number(v.back())+L".";
            }
        }
        for(int i:{5,6})fact(p,s.metrics[i],L" ms");
        for(auto key:{"baseline","download","upload","recovery"}){
            const auto& delays=field(field(t,"phases"),key);if(!delays.is_array())continue;
            auto med=typical_delay(delays);
            metric(p,L"HTTPS · "+phase(key),med?number(*med)+L" ms":L"Za mało odpowiedzi",L"Czas żądania HTTPS w danej fazie. Przerwy na wykresie oznaczają brak próbki.");
            auto& r=p.rows.back();r.unit=L"ms";
            for(auto& d:delays){auto& v=field(d,"ms");r.points.push_back(v.is_number()?std::optional<double>(v.get<double>()):std::nullopt);}
        }
    }else if(page==2){
        const auto& sys=field(inv,"system");fact(p,s.checks[0]);
        metric(p,L"Procesor",value(reading(sys,"cpu_model")),L"Model odczytany przez Windows.");
        metric(p,L"Procesory logiczne",value(field(sys,"logical_processors")),L"Liczba procesorów logicznych widzianych przez system.");
        auto& ram=reading(sys,"memory");
        for(auto key:{"total_bytes","available_bytes"}){auto& v=field(ram,key);metric(p,key[0]=='t'?L"Pamięć RAM":L"Dostępna pamięć",v.is_number()?number(v.get<double>()/1073741824.)+L" GiB":L"Brak odczytu",L"Stan w chwili uruchomienia pomiaru.");}
        for(auto& i:reading(inv,"interfaces"))if(field(i,"oper_status")==1)
            metric(p,L"Aktywna karta",value(reading(i,"model")),L"Sterownik · "+value(reading(i,"driver"))+L"   MTU · "+value(field(i,"mtu")));
    }else if(page==3){
        for(int i:{1,2,5,6,7})fact(p,s.checks[i]);
        if(nic)for(auto& n:reading(inv,"neighbors"))if(field(n,"index")==field(*nic,"index"))
            metric(p,L"Sąsiad na karcie testu",value(field(n,"ip")),L"Wpis w pamięci sąsiadów Windows. Producent · "+value(reading(n,"vendor")));
    }else if(page==4){
        fact(p,s.checks[1]);
        for(auto& r:reading(inv,"wifi")){
            const auto& c=reading(r,"connection");auto& sig=field(c,"signal_pct");
            metric(p,L"Sygnał",sig.is_number()?number(sig.get<double>())+L"%":L"Brak odczytu",L"Jakość sygnału zgłoszona przez Windows w chwili testu.");
            metric(p,L"Kanał",value(reading(r,"channel")),L"Kanał połączenia radiowego.");
            for(auto key:{"rx_kbps","tx_kbps"}){auto& v=field(c,key);metric(p,key[0]=='r'?L"Łącze Wi-Fi · odbiór":L"Łącze Wi-Fi · nadawanie",v.is_number()?number(v.get<double>()/1000)+L" Mb/s":L"Brak odczytu",L"Prędkość negocjowana przez kartę bezprzewodową.");}
        }
        if(!reading(inv,"wifi").is_array() || reading(inv,"wifi").empty())
            metric(p,L"Radio Wi-Fi",L"Brak danych",L"Windows nie udostępnił danych o połączeniu bezprzewodowym w tym raporcie.");
    }else if(page==5){
        for(int i:{2,3,4})fact(p,s.metrics[i],i==4?L" %":L" ms");
        for(auto k:{"gateway","node"}){
            const auto& h=field(field(t,"host_pings"),k);if(!h.is_object())continue;
            double sum=0;
            unsigned count=0;
            for(const auto& probe:field(h,"samples")){
                const auto& ms=field(probe,"rtt_ms");
                if(field(probe,"status")=="echo_reply" && ms.is_number()){sum+=ms.get<double>();++count;}
            }
            auto destination=field(h,"target").is_string()?value(h.at("target")):L"Brak adresu";
            metric(p,k[0]=='g'?L"Ping do routera":L"Ping do węzła",
                count?number(sum/count)+L" ms":L"Brak echa ICMP",
                L"Cel pomiaru\r\n"+destination+L"\r\n\r\nKolejne odpowiedzi ICMP w milisekundach. Luka oznacza brak odczytu.");
            auto& r=p.rows.back();r.unit=L"ms";
            for(auto& a:field(h,"samples")){auto& v=field(a,"rtt_ms");r.points.push_back(v.is_number()?std::optional<double>(v.get<double>()):std::nullopt);}
        }
        p.subtitle=L"Adresy z ostatniego testu. Dwuklik otwiera szczegóły z możliwością kopiowania.";
        if(nic){
            for(const auto& dns:reading(*nic,"dns"))if(dns.is_string())
                metric(p,L"DNS",value(dns),L"Adres serwera skonfigurowanego na karcie pomiarowej.");
            for(const auto& local:reading(*nic,"unicast")){
                const auto& ip=field(local,"ip");
                if(!ip.is_string()) continue;
                auto address=value(ip);
                const bool v6=address.find(L':')!=address.npos;
                metric(p,v6?L"IPv6 · karta":L"IPv4 · karta",address,
                    v6 && address.starts_with(L"fe80:")?L"Adres łącza lokalnego karty.":L"Adres odczytany z karty pomiarowej.");
            }
        }
        const auto& peer=field(t,"peer");
        if(peer.is_string())metric(p,L"Węzeł pomiarowy · IP",value(peer),L"Adres serwera użyty przez aplikację.");
        const auto& seen=field(report,"observed_ip");
        if(seen.is_string()){
            auto ip=value(seen);
            metric(p,ip.find(L':')==ip.npos?L"IPv4 · widziany przez serwer":L"IPv6 · widziany przez serwer",
                ip,L"Adres połączenia zapisany przez serwer pomiarowy HTTPS.");
        }else metric(p,L"IP widziany przez serwer",L"Brak danych",L"Serwer nie podał adresu klienta w ostatnim raporcie.");
        for(int i:{5,6,7})if(s.checks[i].tone==Tone::neutral)fact(p,s.checks[i]);
        fact(p,s.checks[9]);
    }
    return p;
}
}
