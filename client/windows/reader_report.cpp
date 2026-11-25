#include "reader_report.hpp"
#include <algorithm>
#include <array>
#include <cstring>
#include <iomanip>
#include <string_view>
#include <vector>
#include <map>
#include <optional>
#include <set>
#include <sstream>

namespace {
const Json& get(const Json& obj,const char* name) {
    static const Json absent;
    auto it=obj.find(name);
    return it==obj.end() ? absent : *it;
}
std::string number(double value) {
    std::ostringstream out;
    out << std::fixed << std::setprecision(1) << value;
    auto text=out.str();
    if (text.ends_with(".0")) text.resize(text.size()-2);
    std::replace(text.begin(),text.end(),'.',',');
    return text;
}
std::optional<double> speed(const Json& transfer,const char* dir) {
    const auto& t=get(get(transfer,"transfers"),dir);
    const auto& profile=get(transfer,"profile");
    if (!profile.is_object() || get(t,"status")!="ok" || !get(t,"duration_ms").is_number() ||
        t["duration_ms"]<=0 || !get(t,"client_bytes").is_number() || t["client_bytes"]<=0 ||
        t["client_bytes"]!=get(t,"node_bytes") || !get(profile,"bytes").is_number()) return {};
    const auto bytes=t["client_bytes"].get<double>(),limit=profile["bytes"].get<double>();
    if (profile.value("mode","")=="windowed" ? bytes>limit : bytes!=limit) return {};
    return bytes*0.008/t["duration_ms"].get<double>();
}
std::optional<double> typical_delay(const Json& samples) {
    std::vector<double> times;
    for (const auto& sample:samples)
        if (get(sample,"error").is_null() && get(sample,"ms").is_number()) times.push_back(sample.at("ms"));
    if (times.size()<5 || times.size()*5<samples.size()*4) return {};
    std::sort(times.begin(),times.end());
    return (times[(times.size()-1)/2]+times[times.size()/2])/2;
}
const Json* used_adapter(const Json& inv,const Json& transfer) {
    const auto& ip=get(get(transfer,"reservation_local_ip"),"value");
    if (!ip.is_string()) return nullptr;
    const Json* found=nullptr;
    for (const auto& card:get(get(inv,"interfaces"),"value")) {
        for (const auto& addr:get(get(card,"unicast"),"value")) {
            if (get(addr,"ip")!=ip) continue;
            if (found) return nullptr;
            found=&card; break;
        }
    }
    return found;
}
void connection(std::ostream& out,const Json& inv,const Json* card) {
    if (card) {
        int type=card->at("type");
        out << (type==71 ? "Komputer użył sieci Wi-Fi." : type==6 ? "Komputer użył karty Ethernet." :
                type==131 ? "Komputer użył tunelu sieciowego." : "Komputer wyszedł do internetu przez kartę wskazaną w szczegółach.");
        if (type==71) {
            for (const auto& radio:get(get(inv,"wifi"),"value")) {
                auto a=radio.value("id",""), b=card->value("id","");
                if (a.empty() || _stricmp(a.c_str(),b.c_str())) continue;
                const auto& signal=get(get(get(radio,"connection"),"value"),"signal_pct");
                if (signal.is_number()) out << " Windows ocenił siłę sygnału na " << signal << "%.";
            }
            out << " Aby sprawdzić wpływ Wi-Fi, powtórz test na tym samym komputerze po kablu.";
        }
        out << "\r\n";
    }
}

void ping_line(std::ostream& out,const Json& host,const std::string& name) {
    out << name;
    if (get(host,"target").is_string()) out << " (" << host.at("target").get<std::string>() << ")";
    const auto& rows=get(host,"samples");
    if (!rows.is_array() || rows.empty()) {
        auto reason=host.is_object()?host.value("reason",Json(nullptr)):Json(nullptr);
        out << " — " << (reason=="cancelled" ? "test zatrzymano." :
            reason=="no_separate_gateway" ? "Windows nie wskazał osobnego routera na tej trasie." :
            reason=="route_changed" ? "połączenie zmieniło się podczas testu." :
            "brak pomiaru dla tego celu.") << "\r\n";
        return;
    }
    size_t replies=0, local=0, timeouts=0;
    double sum=0;
    for (const auto& row:rows) {
        if (row.at("status")=="echo_reply" && row.at("responder")==host.at("target") && row.at("rtt_ms").is_number()) {
            ++replies; sum+=row.at("rtt_ms").get<double>();
        } else if (row.at("status")=="unavailable") ++local;
        else if (row.at("status")=="timeout") ++timeouts;
    }
    out << " — ";
    if (replies) out << "średnio " << number(sum/replies) << " ms, ";
    if (rows.size()>local) out << "odpowiedzi " << replies << " z " << rows.size()-local << ".";
    else out << "brak wysłanych prób.";
    if (timeouts) out << " Bez odpowiedzi w ciągu 400 ms: " << timeouts << ".";
    if (local) out << " Liczba prób, których Windows nie mógł wykonać: " << local << ".";
    if (rows.size()<5) out << " Seria niepełna.";
    out << "\r\n";
}

void route_loss(std::ostream& out,const Json& rows,const Json& peer) {
    bool noted=false, had_data=false;
    const std::array<std::pair<const char*,const char*>,4> phases={{{"baseline","Przed testem"},{"download","Podczas pobierania"},
        {"upload","Podczas wysyłania"},{"recovery","Po teście"}}};
    for (auto [phase,label]:phases) {
        struct Hop {int timeout{}, received{}, unreachable{}; std::set<std::string> ips; std::set<int> timed, valid;};
        std::map<int,Hop> hops;
        std::set<int> end, attempts;
        for (const auto& s:rows) {
            if (s.at("phase")!=phase || s.at("protocol")!="icmp" || s.at("target")!=peer) continue;
            const int attempt=s.at("attempt");
            attempts.insert(attempt);
            if (s.at("status")=="unavailable") continue;
            had_data=true;
            auto ttl=s.at("ttl").get<int>(); auto& hop=hops[ttl];
            if (s.at("status")=="timeout") {++hop.timeout; hop.timed.insert(attempt); hop.valid.insert(attempt); continue;}
            if (s.at("responder").is_string()) {
                if (s.at("status")=="ttl_expired" || (s.at("status")=="echo_reply" && s.at("responder")==peer)) hop.valid.insert(attempt);
                if (s.at("status")=="unreachable") ++hop.unreachable;
                ++hop.received; hop.ips.insert(s.at("responder").get<std::string>());
                if (s.at("status")=="echo_reply" && s.at("responder")==peer) end.insert(ttl);
            }
        }
        std::ostringstream missing; bool any=false;
        for (const auto& [ttl,h]:hops) {
            if (h.unreachable) {
                noted=true;
                out << label << " — na etapie " << ttl << " zgłoszono, że cel jest nieosiągalny. ";
                for (const auto& ip:h.ips) out << ip << " ";
                out << "\r\n";
            }
            if (!h.timeout) continue;
            missing << (any?" oraz ":"") << "etap " << ttl;
            for (const auto& ip:h.ips) missing << " (" << ip << ")";
            missing << " — " << h.timeout << " z " << h.received+h.timeout << " prób";
            any=true;
        }
        if (any) {
            noted=true;
            out << label << " — brak odpowiedzi: " << missing.str() << ". ";
            if (end.empty()) out << "Ta seria nie potwierdziła odpowiedzi serwera.";
            else if (end.size()==1 && hops.at(*end.begin()).timeout) {
                const int last=*end.begin();
                int first=last;
                const auto& end_hop=hops.at(last);
                if (attempts.size()>=5 && end_hop.valid==attempts && end_hop.timed.size()>=2) {
                    while (first>1 && hops.count(first-1)) {
                        const auto& h=hops.at(first-1);
                        if (h.valid!=attempts || !std::includes(h.timed.begin(),h.timed.end(),end_hop.timed.begin(),end_hop.timed.end())) break;
                        --first;
                    }
                }
                if (first<last) out << "W tych samych rundach odpowiedzi brakowało od etapu " << first << " aż do serwera. ";
                out << "Brakowało też odpowiedzi na etapie serwera. Dokładne miejsce utraty pozostaje nieustalone.";
            }
            else out << "Serwer odpowiadał. Router po drodze może rzadziej odpowiadać na ping, mimo że przekazuje dane dalej.";
            out << "\r\n";
        }
    }
    if (!noted) out << (had_data ? "W wykonanych próbach śledzenia trasy nie upłynął czas oczekiwania na odpowiedź." :
                                   "Brakuje pomiaru trasy, który pozwala wskazać miejsce problemu.") << "\r\n";
}
}

std::string reader_report(const Json& report) {
    const auto& t=report.at("throughput");
    const auto& inv=get(report,"inventory");
    const auto* card=used_adapter(inv,t);
    auto down=speed(t,"download"), up=speed(t,"upload");
    std::ostringstream out;
    const bool interrupted=get(get(get(t,"host_pings"),"node"),"reason")=="cancelled";
    out << (t.at("error").is_null() && !interrupted ? "Twój wynik" : "Twój wynik częściowy") << "\r\n\r\n";
    out << "Prędkość pobierania: " << (down ? number(*down)+" Mb/s" : "brak pełnego pomiaru") << "\r\n";
    out << "Prędkość wysyłania: " << (up ? number(*up)+" Mb/s" : "brak pełnego pomiaru") << "\r\n";
    if (t.at("error")=="cancelled" || interrupted) out << "Test zatrzymano. Wyniki ukończonych prób są zapisane poniżej.\r\n";
    out << "Pobieranie określa, jak szybko plik trafia na komputer. Wysyłanie — jak szybko możesz przesłać go innej osobie.\r\n\r\n";
    out << "Co mogło ograniczyć prędkość?\r\n";
    const auto& cap=get(get(t,"profile"),"rate_bps");
    if (cap.is_number() && cap.get<double>()>0) {
        auto mbps=cap.get<double>()/1e6;
        out << "Serwer mierzył do " << number(mbps) << " Mb/s. ";
        if (down && *down>=mbps*.9) out << "Pobieranie zbliżyło się do tej granicy. ";
        if (up && *up>=mbps*.9) out << "Wysyłanie zbliżyło się do tej granicy. ";
        out << "Szybkość pakietu możesz porównać z wartością w umowie.\r\n";
    }
    connection(out,inv,card);
    if (card) {
        const auto& link=get(get(*card,"link"),"value");
        if (get(link,"rx_bps").is_number() && get(link,"tx_bps").is_number()) {
            out << "Windows podał dla łącza karty " << number(link.at("rx_bps").get<double>()/1e6) << " Mb/s odbioru i "
                << number(link.at("tx_bps").get<double>()/1e6) << " Mb/s wysyłania. Część tej prędkości zajmuje obsługa połączenia.\r\n";
            if (get(*card,"type")==6 && cap.is_number() &&
                std::min(link.at("rx_bps").get<double>(),link.at("tx_bps").get<double>())<cap.get<double>())
                out << "W co najmniej jednym kierunku karta uzgodniła po kablu mniejszą prędkość niż limit testu. Jeśli masz szybszy pakiet, sprawdź kabel i port routera.\r\n";
        }
    }
    out << "Jeden pomiar do jednego serwera nie rozstrzyga, czy ograniczeniem było łącze domowe, trasa w internecie czy sam serwer.\r\n";
    const auto& phases=get(t,"phases");
    if (const auto base=typical_delay(get(phases,"baseline"));base) {
        out << "Typowy czas odpowiedzi strony testowej przed obciążeniem wynosił " << number(*base) << " ms";
        for (auto name:{"download","upload"}) {
            auto under=typical_delay(get(phases,name));
            if (under) out << (std::string_view(name)=="download"?", przy pobieraniu ":", przy wysyłaniu ") << number(*under) << " ms";
        }
        out << ".\r\n";
    }
    const auto& count=get(get(inv,"unique_neighbor_macs"),"value");
    if (count.is_number()) out << "Urządzenia zauważone przez Windows na wszystkich kartach: " << count
        << ". Mogą to być także routery i telefony.\r\n";
    out << "\r\nPing — jak długo czekasz na odpowiedź?\r\n";
    const auto& hosts=get(t,"host_pings");
    if (hosts.is_object()) {
        ping_line(out,hosts.at("gateway"),"Router na drodze do internetu");
        ping_line(out,hosts.at("node"),"Serwer pomiarowy "+(get(t,"node_id").is_string()?t.at("node_id").get<std::string>():""));
        out << "Im krótszy czas w milisekundach (ms), tym szybciej dociera odpowiedź.\r\n";
    } else out << "Ta wersja zapisu nie zawiera oddzielnych pingów do routera i serwera.\r\n";
    out << "\r\nGdzie zabrakło odpowiedzi po drodze?\r\n";
    route_loss(out,get(report,"mtr_samples"),get(t,"peer"));
    out << "\r\nTwoje adresy\r\n";
    if (get(report,"observed_ip").is_string())
        out << "Adres widoczny dla serwera: " << report.at("observed_ip").get<std::string>() << "\r\n";
    if (card) {
        for (bool v6:{false,true}) {
            out << (v6?"IPv6 na komputerze: ":"IPv4 na komputerze: ");
            std::string ips;
            for (const auto& a:get(get(*card,"unicast"),"value")) {
                auto ip=a.at("ip").get<std::string>();
                if ((ip.find(':')!=std::string::npos)==v6) {if (!ips.empty()) ips+=", ";ips+=ip;}
            }
            out << (ips.empty()?"brak w pomiarze":ips) << "\r\n";
        }
    } else out << "Adresy kart znajdziesz w szczegółach, jeśli Windows je zapisał.\r\n";
    out << (report.at("synchronized")==true?"Raport dostępny w panelu klienta.":"Raport zapisano na komputerze. Czeka na wysłanie.");
    return out.str();
}
