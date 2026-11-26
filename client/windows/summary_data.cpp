#include "summary_data.hpp"
#include <algorithm>
#include <cmath>
#include <iomanip>
#include <set>
#include <sstream>

namespace summary {
std::wstring from_utf8(const std::string& s) {
    if (s.empty()) return {};
    const auto count=MultiByteToWideChar(CP_UTF8,0,s.data(),static_cast<int>(s.size()),nullptr,0);
    std::wstring out(count,L' ');
    MultiByteToWideChar(CP_UTF8,0,s.data(),static_cast<int>(s.size()),out.data(),count);
    return out;
}
std::wstring number(double value) {
    std::wostringstream stream;
    stream<<std::fixed<<std::setprecision(1)<<value;
    auto s=stream.str();
    if (s.ends_with(L".0")) s.resize(s.size()-2);
    std::replace(s.begin(),s.end(),L'.',L',');
    return s;
}
std::vector<Point> rates(const Json& rows) {
    std::vector<Point> result;
    if (!rows.is_array() || rows.size()>1024) return result;
    long long previous_time=-1,previous_bytes=0;
    for (const auto& row:rows) {
        if (!row.is_array() || row.size()!=2 || !row[0].is_number_integer() || !row[1].is_number_integer()) return {};
        const auto t=row[0].get<long long>(), bytes=row[1].get<long long>();
        if (t<=previous_time || bytes<previous_bytes || (previous_time<0 && (t!=0 || bytes!=0))) return {};
        if (previous_time>=0) result.push_back({t/1000.0,(bytes-previous_bytes)*0.008/(t-previous_time)});
        previous_time=t;previous_bytes=bytes;
    }
    return result;
}
namespace {
std::wstring string_value(const Json& v) { return v.is_string()?from_utf8(v.get<std::string>()):L""; }
const Json& value(const Json& v,const char* name) { return field(field(v,name),"value"); }
std::optional<IN6_ADDR> parse_ipv6(std::wstring_view address) {
    std::wstring ip(address.substr(0,address.find(L'%')));
    IN6_ADDR bytes{};
    if (InetPtonW(AF_INET6,ip.c_str(),&bytes)!=1) return {};
    return bytes;
}
struct Echo {
    size_t received{},timeouts{};
    std::optional<double> ping,jitter;
    bool complete{};
};
Echo echoes(const Json& host) {
    Echo e;
    double sum=0,change=0;
    std::optional<double> prev;
    size_t pairs=0;
    const auto& attempts=field(host,"samples");
    for (const auto& p:attempts) {
        if (field(p,"status")=="echo_reply" && field(p,"responder")==field(host,"target") && field(p,"rtt_ms").is_number()) {
            double n=p.at("rtt_ms").get<double>();
            sum+=n;++e.received;
            if (prev) {change+=std::abs(n-*prev);++pairs;}
            prev=n;
        } else {
            if (field(p,"status")=="timeout") ++e.timeouts;
            prev.reset();
        }
    }
    if (e.received) e.ping=sum/e.received;
    if (pairs) e.jitter=change/pairs;
    e.complete=field(host,"planned").is_number_integer() && host["planned"]==e.received+e.timeouts &&
               field(host,"reason").is_null() && e.received+e.timeouts>0;
    return e;
}
void measured(Fact& f,std::wstring v,std::wstring detail,Tone tone=Tone::observed) {
    f.value=std::move(v);f.detail=std::move(detail);f.tone=tone;
}
}
bool link_local_v6(std::wstring_view value){
    auto bytes=parse_ipv6(value);
    return bytes && IN6_IS_ADDR_LINKLOCAL(&*bytes);
}
std::vector<Ipv6Address> ipv6_addresses(const Json& report,const Json* adapter) {
    enum Scope : size_t { observed, global, private_ula, other, link_local, scope_count };
    std::array<std::vector<Ipv6Address>,scope_count> groups;
    auto append=[&](std::wstring ip,const std::wstring& source,bool server) {
        auto bytes=parse_ipv6(ip);
        if (!bytes || IN6_IS_ADDR_UNSPECIFIED(&*bytes) || IN6_IS_ADDR_LOOPBACK(&*bytes) ||
            IN6_IS_ADDR_MULTICAST(&*bytes) || IN6_IS_ADDR_V4MAPPED(&*bytes)) return;
        const auto first=bytes->u.Byte[0];
        const auto scope=IN6_IS_ADDR_LINKLOCAL(&*bytes)?link_local:
            server?observed:(first&0xe0)==0x20?global:(first&0xfe)==0xfc?private_ula:other;
        constexpr std::array labels{L"IPv6 · widziany przez serwer",L"IPv6 · globalny",L"IPv6 · prywatny (ULA)",
                                    L"IPv6 · inny zakres",L"IPv6 · link-local"};
        constexpr std::array notes{L"Adres klienta zarejestrowany przy połączeniu HTTPS.",
            L"Adres z zakresu globalnego. Odczyt karty sam nie potwierdza łączności IPv6.",
            L"Adres prywatny ULA, przeznaczony do komunikacji w sieciach prywatnych.",
            L"Adres IPv6 spoza typowych zakresów globalnego, ULA i link-local.",
            L"Adres lokalny dla jednego łącza."};
        const auto detail=source+L"\r\n"+notes[scope];
        auto& group=groups[scope];
        if (std::none_of(group.begin(),group.end(),[&](const auto& entry){
                return entry.address==ip && entry.detail==detail;
            }))
            group.push_back({std::move(ip),labels[scope],detail});
    };
    append(string_value(field(report,"observed_ip")),L"Węzeł pomiarowy",true);
    auto add_card=[&](const Json& card,const std::wstring& source){
        for (const auto& entry:value(card,"unicast")) {
            const auto& dad=field(entry,"dad_state");
            if (dad.is_number_integer() && dad!=3 && dad!=4) continue;
            append(string_value(field(entry,"ip")),source,false);
        }
    };
    if (adapter) add_card(*adapter,L"Karta pomiarowa");
    for (const auto& card:value(field(report,"inventory"),"interfaces")) {
        if (&card==adapter || field(card,"oper_status")!=1 || field(card,"type")==24) continue;
        auto model=string_value(value(card,"model"));
        add_card(card,model.empty()?L"Inna aktywna karta":L"Inna aktywna karta · "+model);
    }
    std::vector<Ipv6Address> result;
    for (auto& group:groups) for (auto& entry:group) result.push_back(std::move(entry));
    return result;
}
std::vector<std::wstring> display_dns(const Json& adapter){
    std::vector<std::wstring> result,ipv6;
    for(const auto& item:value(adapter,"dns")){
        if(!item.is_string())continue;
        const auto& address=item.get_ref<const std::string&>();
        try {
            auto target=parse_target(address.c_str());
            auto text=from_utf8(target.text);
            if(!target.ipv6()){
                if(result.empty())result.push_back(std::move(text));
            }else if(ipv6.size()<2 && public_game_target(target) &&
                std::find(ipv6.begin(),ipv6.end(),text)==ipv6.end())ipv6.push_back(std::move(text));
        }catch(const std::invalid_argument&){}
    }
    result.insert(result.end(),ipv6.begin(),ipv6.end());
    return result;
}
Snapshot read(const Json& report) {
    Snapshot s;
    const wchar_t* metric_names[]={L"Pobieranie",L"Wysyłanie",L"Ping",L"Wahanie pingu",L"Utrata odpowiedzi",L"Opóźnienie pobierania",L"Opóźnienie wysyłania"};
    constexpr std::array<const wchar_t*,check_count> names{L"Komputer",L"Połączenie",L"Sieć lokalna",L"Sieć operatora",
        L"DNS",L"IPv4",L"IPv6",L"Stabilność połączenia",L"Opóźnienie pod obciążeniem"};
    for (size_t i=0;i<s.metrics.size();++i) s.metrics[i]={metric_names[i],L"—",L"Brak wystarczających próbek tej metryki."};
    for (size_t i=0;i<s.checks.size();++i) s.checks[i]={names[i],L"Nie przetestowano",L"Ten test nie zawiera osobnej próby tego obszaru."};
    s.finding=L"Rozpocznij test, aby sprawdzić swoje połączenie.";
    s.finding_detail=L"Program zmierzy transfer i czas odpowiedzi serwera oraz odczyta stan sieci na komputerze.";
    s.save_status=L"Brak raportu";s.last=L"Brak wcześniejszego testu";
    const auto& t=field(report,"throughput");
    if (!t.is_object()) return s;
    s.recorded=true;s.partial=!field(t,"error").is_null() ||
        field(field(field(t,"host_pings"),"gateway"),"reason")=="cancelled" ||
        field(field(field(t,"host_pings"),"node"),"reason")=="cancelled";s.synced=field(report,"synchronized")==true;
    s.last=string_value(field(t,"ended_at"));
    if (s.last.empty()) s.last=string_value(field(t,"started_at"));
    if (s.last.size()>=19) s.last=s.last.substr(0,10)+L"  "+s.last.substr(11,8)+L" UTC";
    s.save_status=s.synced?L"Zapisano w panelu":L"Zapisano lokalnie";
    const auto& trace=report.contains("desktop_trace")?report["desktop_trace"]:field(t,"desktop_trace");
    const auto& phases=field(t,"phases");
    auto base=typical_delay(field(phases,"baseline"));
    std::optional<double> worst_delta;
    size_t worst_direction=0;
    for (size_t i=0;i<2;++i) {
        auto dir=i?"upload":"download";
        s.speed_mbps[i]=speed(t,dir);
        if (auto v=s.speed_mbps[i]) measured(s.metrics[i],number(*v),L"Średnia z całego transferu potwierdzonego przez węzeł pomiarowy, w Mb/s.");
        if (field(trace,"session_id").is_string() && trace["session_id"]==field(t,"session_id"))
            s.lines[i]=rates(field(trace,dir));
        if (auto d=typical_delay(field(phases,dir))) {
            measured(s.metrics[5+i],number(*d),L"Mediana czasu odpowiedzi usługi HTTPS podczas transferu, w milisekundach.");
            if (base && (!worst_delta || *d-*base>*worst_delta)) {worst_delta=*d-*base;worst_direction=i;}
        }
    }
    const auto& host=field(field(t,"host_pings"),"node");
    const auto e=echoes(host);
    if (e.ping) measured(s.metrics[2],number(*e.ping),L"Średni czas odpowiedzi ICMP serwera pomiarowego, w ms. Odpowiedzi: "+std::to_wstring(e.received)+L".");
    if (e.jitter) measured(s.metrics[3],number(*e.jitter),L"Średnia bezwzględna różnica czasu kolejnych odpowiedzi ICMP (ms). Przerwa rozdziela pary.");
    if (e.complete) measured(s.metrics[4],number(100.0*e.timeouts/(e.received+e.timeouts)),
        L"Odsetek prób ICMP do serwera zakończonych timeoutem. Próby bez odpowiedzi: "+std::to_wstring(e.timeouts)+
        L" z "+std::to_wstring(e.received+e.timeouts)+L".",e.timeouts?Tone::warning:Tone::observed);
    const auto& inv=field(report,"inventory");
    auto cpu=string_value(value(field(inv,"system"),"cpu_model"));
    if (!cpu.empty()) measured(s.checks[check_computer],L"Odczytano parametry",cpu);
    auto nic=used_adapter(inv,t);
    if (nic) {
        auto kind=field(*nic,"type");
        auto label=kind==71?L"Wi-Fi":kind==6?L"Ethernet":kind==131?L"Tunel":L"Karta sieciowa";
        measured(s.checks[check_connection],label,string_value(value(*nic,"model")));
        for (const auto& radio:value(inv,"wifi")) {
            auto id=string_value(field(radio,"id")),matched=string_value(field(*nic,"id"));
            if (kind!=71 || id.empty() || _wcsicmp(id.c_str(),matched.c_str())) continue;
            const auto& signal=field(value(radio,"connection"),"signal_pct");
            if (signal.is_number()) s.checks[check_connection].value+=L" · "+number(signal.get<double>())+L"% sygnału";
        }
        const auto& neighbors=value(inv,"neighbors");
        if (neighbors.is_array()) {
            std::set<std::string> macs;
            for (const auto& row:neighbors) {
                auto& id=value(row,"mac_id");
                if (id.is_string() && field(row,"index")==field(*nic,"index")) macs.insert(id.get<std::string>());
            }
            std::wstring count=field(field(inv,"neighbors"),"status")=="partial"?L"≥ ":L"";
            measured(s.checks[check_lan],L"Widoczne urządzenia: "+count+std::to_wstring(macs.size()),
                L"Różne adresy urządzeń w pamięci sąsiadów Windows na karcie testu. Jeden komputer może używać wielu adresów.");
        }
        for (const auto& addr:value(*nic,"unicast")) {
            auto ip=string_value(field(addr,"ip"));
            if (ip.empty() || ip.find(L':')!=ip.npos) continue;
            auto& check=s.checks[check_ipv4];
            if (check.tone==Tone::neutral) measured(check,ip,ip);
            else check.detail+=L"\r\n"+ip;
        }
        const auto dns=display_dns(*nic);
        if(!dns.empty()){
            std::wstring addresses;
            for(const auto& address:dns)addresses+=address+L"\r\n";
            if(std::none_of(dns.begin(),dns.end(),[](const auto& address){return address.find(L':')!=address.npos;}))
                addresses+=L"DNS IPv6 · Nieskonfigurowane";
            measured(s.checks[check_dns],dns.front()+(dns.size()>1?L"  +"+std::to_wstring(dns.size()-1):L""),
                L"Jeden DNS IPv4 i maksymalnie dwa publiczne DNS IPv6 z karty testu\r\n"+addresses);
        }else measured(s.checks[check_dns],L"Nieskonfigurowane",L"Brak DNS IPv4 do pokazania.\r\nDNS IPv6 · Nieskonfigurowane.",Tone::neutral);
    }
    auto observed=string_value(field(report,"observed_ip"));
    if (!observed.empty() && observed.find(L':')==observed.npos) {
        auto& family=s.checks[check_ipv4];
        auto detail=family.tone==Tone::observed ? L"Adresy lokalne karty\r\n"+family.detail+L"\r\n\r\n" : L"";
        measured(family,observed,detail+L"Adres klienta widziany przez węzeł HTTPS\r\n"+observed);
    }
    const auto addresses=ipv6_addresses(report,nic);
    if (!addresses.empty()) {
        std::wstring details;
        for (const auto& entry:addresses) {
            if (!details.empty()) details+=L"\r\n\r\n";
            details+=entry.label+L"\r\n"+entry.address+L"\r\n"+entry.detail;
        }
        const bool only_link_local=link_local_v6(addresses.front().address);
        measured(s.checks[check_ipv6],only_link_local?L"Tylko link-local":addresses.front().address,
                 std::move(details),only_link_local?Tone::neutral:Tone::observed);
    } else measured(s.checks[check_ipv6],L"Brak adresu",L"Brak dostępnego adresu IPv6 w zapisanych danych pomiaru.",Tone::neutral);
    if (e.complete) measured(s.checks[check_stability],e.timeouts?L"Brak części odpowiedzi":L"Serwer odpowiedział",
        s.metrics[4].detail+L" Krótka seria dotyczy wyłącznie chwili testu.",e.timeouts?Tone::warning:Tone::observed);
    if (!worst_delta && (s.metrics[5].tone==Tone::observed || s.metrics[6].tone==Tone::observed))
        measured(s.checks[check_latency],L"Brak porównania",L"Zapisano opóźnienia pod obciążeniem. Brakuje wystarczającej liczby odpowiedzi w spoczynku.",Tone::neutral);
    if (worst_delta) {
        auto delta=std::max(0.0,*worst_delta);
        measured(s.checks[check_latency],L"Wzrost o "+number(delta)+L" ms",L"Największy wzrost mediany czasu HTTPS względem spoczynku w zmierzonych kierunkach.",
                 delta>=20?Tone::warning:Tone::observed);
    }
    if (s.partial) {
        s.finding=L"Test częściowy. Zachowano wykonane pomiary.";
        s.action=L"Otwórz raport, aby sprawdzić przyczynę i ukończone próby.";
        s.finding_detail=field(t,"error").is_string()?L"Przyczyna zapisana przez silnik: "+string_value(field(t,"error")):L"Zatrzymano pomiar ping. Ukończone transfery są dostępne w raporcie.";
        s.finding_tone=Tone::warning;
    } else if (e.complete && e.timeouts) {
        s.finding=L"Brak odpowiedzi na "+std::to_wstring(e.timeouts)+L" z "+std::to_wstring(e.received+e.timeouts)+L" prób ping.";
        s.action=L"Rozmowy mogą przerywać. Powtórz test i porównaj trasę MTR.";
        s.finding_detail=s.metrics[4].detail+L" Powtórz pomiar i porównaj trasę MTR.";
        s.finding_tone=Tone::warning;
    } else if (worst_delta && *worst_delta>=20) {
        s.finding=std::wstring(L"Podczas ")+(worst_direction?L"wysyłania":L"pobierania")+L" opóźnienie wzrosło o "+number(*worst_delta)+L" ms.";
        s.action=L"Gry i rozmowy mogą reagować wolniej. Powtórz test bez innych transferów.";
        s.finding_detail=L"Rozmowy i gry mogą reagować wolniej. Powtórz test bez innych transferów, najlepiej po kablu.";
        s.finding_tone=Tone::warning;
    } else if (e.complete && worst_delta && s.metrics[5].tone==Tone::observed && s.metrics[6].tone==Tone::observed && s.metrics[0].tone==Tone::observed && s.metrics[1].tone==Tone::observed) {
        s.finding=L"Serwer odpowiedział na każdy ping. Wzrost opóźnienia poniżej 20 ms.";
        s.finding_detail=L"Wniosek dotyczy krótkiego pomiaru do wybranego serwera. Pełny raport zawiera liczbę prób i przebieg trasy.";
        s.finding_tone=Tone::observed;
    } else {
        s.finding=L"Pomiar zakończony. Część ocen wymaga dodatkowych próbek.";
        s.finding_detail=L"Otwórz szczegóły danej metryki, aby sprawdzić jej źródło i dostępność.";
    }
    return s;
}
}
