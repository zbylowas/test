#include "live_diagnostics.hpp"
#include "queue.hpp"
#include <windns.h>
#include <algorithm>
#include <map>
#include <set>
#include <memory>
#include <thread>

namespace summary {
namespace {
using Clock=std::chrono::steady_clock;
struct SocketSnapshot {
    std::map<std::pair<std::wstring,ULONG>,std::set<unsigned>> remote_ports;
};
template<class F> void load_table(F fetch, std::vector<unsigned char>& buffer) {
    DWORD size=0;
    auto status=fetch(nullptr,&size);
    if(status!=ERROR_INSUFFICIENT_BUFFER || !size || size>64*1024*1024)return;
    for(int tries=0;tries<3;++tries){
        buffer.resize(size);
        status=fetch(buffer.data(),&size);
        if(status==NO_ERROR)return;
        if(status!=ERROR_INSUFFICIENT_BUFFER || size>64*1024*1024)break;
    }
    buffer.clear();
}
std::wstring ip_text(int family,const void* addr) {
    wchar_t out[INET6_ADDRSTRLEN]{};
    return InetNtopW(family,addr,out,static_cast<DWORD>(std::size(out)))?out:L"";
}
template<class Table> void tcp_rows(const Table& table,SocketSnapshot& result) {
    for(DWORD i=0;i<table.dwNumEntries;++i){
        const auto& row=table.table[i];
        if(row.dwState!=MIB_TCP_STATE_ESTAB)continue;
        std::wstring address;
        ULONG scope=0;
        if constexpr(requires {row.dwRemoteScopeId;}) {
            address=ip_text(AF_INET6,row.ucRemoteAddr);
            scope=row.dwRemoteScopeId;
        } else address=ip_text(AF_INET,&row.dwRemoteAddr);
        auto port=ntohs(static_cast<u_short>(row.dwRemotePort));
        if(!address.empty() && port)result.remote_ports[{address,scope}].insert(port);
    }
}
SocketSnapshot sockets() {
    SocketSnapshot result;
    for(int family:{AF_INET,AF_INET6}){
        std::vector<unsigned char> raw;
        load_table([family](void* data,DWORD* size){return GetExtendedTcpTable(data,size,FALSE,family,TCP_TABLE_OWNER_PID_CONNECTIONS,0);},raw);
        if(raw.empty())continue;
        if(family==AF_INET)tcp_rows(*reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(raw.data()),result);
        else tcp_rows(*reinterpret_cast<const MIB_TCP6TABLE_OWNER_PID*>(raw.data()),result);
    }
    return result;
}
unsigned long long ticks(FILETIME value){
    return (static_cast<unsigned long long>(value.dwHighDateTime)<<32)|value.dwLowDateTime;
}
struct Cpu { unsigned long long idle{}, total{}; };
std::optional<Cpu> cpu_time(){
    FILETIME idle{}, kernel{}, user{};
    if(!GetSystemTimes(&idle,&kernel,&user))return {};
    return Cpu{ticks(idle),ticks(kernel)+ticks(user)};
}
using InterfaceCounters=std::map<ULONG64,MIB_IF_ROW2>;
InterfaceCounters links() {
    InterfaceCounters result;
    MIB_IF_TABLE2* raw=nullptr;
    if(GetIfTable2(&raw)!=NO_ERROR)return result;
    std::unique_ptr<MIB_IF_TABLE2,decltype(&FreeMibTable)> table(raw,FreeMibTable);
    for(ULONG i=0;i<table->NumEntries;++i){
        const auto& row=table->Table[i];
        if(row.OperStatus==IfOperStatusUp && row.Type!=IF_TYPE_SOFTWARE_LOOPBACK)
            result.emplace(row.InterfaceLuid.Value,row);
    }
    return result;
}
std::wstring service_label(unsigned port){
    switch(port){
    case 22:return L"SSH (22)";
    case 53:return L"DNS (53)";
    case 80:return L"HTTP (80)";
    case 443:return L"HTTPS (443)";
    case 445:return L"SMB (445)";
    case 631:return L"IPP (631)";
    case 3389:return L"RDP (3389)";
    default:return std::to_wstring(port);
    }
}
std::wstring mac_text(const UCHAR* bytes) {
    std::wstring result;
    constexpr wchar_t hex[]=L"0123456789ABCDEF";
    for(unsigned i=0;i<6;++i){
        if(i)result+=L':';
        result+=hex[bytes[i]>>4];result+=hex[bytes[i]&15];
    }
    return result;
}
std::wstring cached_hostname(const SOCKADDR_INET& address) {
    std::wstring query;
    if(address.si_family==AF_INET){
        auto* bytes=reinterpret_cast<const unsigned char*>(&address.Ipv4.sin_addr);
        for(int j=3;j>=0;--j)query+=std::to_wstring(bytes[j])+L".";
        query+=L"in-addr.arpa.";
    }else if(address.si_family==AF_INET6){
        const auto& ip=address.Ipv6.sin6_addr;
        if(IN6_IS_ADDR_LINKLOCAL(&ip))return {};
        constexpr wchar_t hex[]=L"0123456789abcdef";
        for(int j=15;j>=0;--j){
            query+=hex[ip.s6_addr[j]&15];query+=L'.';
            query+=hex[ip.s6_addr[j]>>4];query+=L'.';
        }
        query+=L"ip6.arpa.";
    }else return {};
    PDNS_RECORDW records=nullptr;
    auto flags=DNS_QUERY_NO_WIRE_QUERY|DNS_QUERY_NO_MULTICAST|DNS_QUERY_NO_NETBT;
    if(DnsQuery_W(query.c_str(),DNS_TYPE_PTR,flags,nullptr,&records,nullptr)!=ERROR_SUCCESS || !records)
        return {};
    std::unique_ptr<DNS_RECORDW,decltype([](PDNS_RECORDW p){DnsFree(p,DnsFreeRecordList);})> list(records);
    for(auto row=list.get();row;row=row->pNext){
        if(row->wType!=DNS_TYPE_PTR || !row->Data.PTR.pNameHost)continue;
        std::wstring name=row->Data.PTR.pNameHost;
        if(name.ends_with(L"."))name.pop_back();
        if(!name.empty() && name.size()<=253)return name;
    }
    return {};
}
std::wstring report_time(){
    return L"Odczyt "+from_utf8(utc_now())+L" · ";
}
}
DetailPage live_computer(const DetailPage& previous) {
    auto started=Clock::now();
    const auto before_cpu=cpu_time();
    const auto before_links=links();
    std::this_thread::sleep_until(started+std::chrono::milliseconds(600));
    const auto after_cpu=cpu_time();
    const auto after_links=links();
    const double elapsed=std::chrono::duration<double>(Clock::now()-started).count();
    DetailPage page{report_time()+L"Stan komputera. Ruch poszczególnych procesów można włączyć w Podsumowaniu.",
        {{L"Parametr",253},{L"Wartość",275}},{}};
    MEMORYSTATUSEX memory{};memory.dwLength=sizeof memory;
    page.rows.push_back({{L"RAM teraz",GlobalMemoryStatusEx(&memory)?std::to_wstring(memory.dwMemoryLoad)+L" % zajęte":L"Brak odczytu"},
        L"Procent zajętej pamięci fizycznej zgłoszony przez Windows.",{},{}});
    std::wstring cpu=L"Brak odczytu";
    if(before_cpu && after_cpu && after_cpu->total>before_cpu->total && after_cpu->idle>=before_cpu->idle){
        const double use=1.0-double(after_cpu->idle-before_cpu->idle)/(after_cpu->total-before_cpu->total);
        cpu=number(std::clamp(100*use,0.0,100.0))+L" %";
    }
    page.rows.push_back({{L"CPU teraz",cpu},L"Łączne użycie procesora podczas odczytu.",{},{}});
    for(const auto& [id,iface]:after_links){
        auto prior=before_links.find(id);
        if(prior==before_links.end() || iface.InOctets<prior->second.InOctets || iface.OutOctets<prior->second.OutOctets)continue;
        auto receive=number((iface.InOctets-prior->second.InOctets)*8.0/(elapsed*1e6));
        auto sent=number((iface.OutOctets-prior->second.OutOctets)*8.0/(elapsed*1e6));
        page.rows.push_back({{std::wstring(L"Ruch · ")+iface.Alias,receive+L" / "+sent+L" Mb/s"},
            L"Średni ruch pobierania i wysyłania tej karty podczas odczytu, w tym komunikacja lokalna.",{},{}});
    }
    for(const auto& row:previous.rows)page.rows.push_back(row);
    return page;
}
DetailPage live_lan(){
    DetailPage page{report_time()+L"Urządzenia znane karcie i połączenia TCP widoczne na tym komputerze.",
        {{L"Adres IP",193},{L"Adres MAC",148},{L"Hostname",167},{L"Producent MAC",155},{L"Rola",110},{L"Porty TCP",135}},{}};
    MIB_IPNET_TABLE2* raw=nullptr;
    auto error=GetIpNetTable2(AF_UNSPEC,&raw);
    std::unique_ptr<MIB_IPNET_TABLE2,decltype(&FreeMibTable)> neighbors(raw,FreeMibTable);
    if(error){
        page.rows.push_back({{L"Brak odczytu"},L"GetIpNetTable2 · kod Windows "+std::to_wstring(error),{},{}});
        return page;
    }
    const auto connections=sockets();
    const auto interfaces=links();
    const auto registry=read_oui_registry();
    MIB_IPFORWARD_TABLE2* routes_raw=nullptr;
    GetIpForwardTable2(AF_UNSPEC,&routes_raw);
    std::unique_ptr<MIB_IPFORWARD_TABLE2,decltype(&FreeMibTable)> routes(routes_raw,FreeMibTable);
    std::set<std::pair<ULONG,std::wstring>> gateways;
    if(routes)for(ULONG j=0;j<routes->NumEntries;++j){
        const auto& route=routes->Table[j];
        if(route.DestinationPrefix.PrefixLength!=0)continue;
        const auto& hop=route.NextHop;
        auto address=ip_text(hop.si_family,hop.si_family==AF_INET?static_cast<const void*>(&hop.Ipv4.sin_addr):
            static_cast<const void*>(&hop.Ipv6.sin6_addr));
        gateways.emplace(route.InterfaceIndex,std::move(address));
    }
    for(ULONG i=0;i<neighbors->NumEntries && page.rows.size()<256;++i){
        const auto& n=neighbors->Table[i];
        if(n.PhysicalAddressLength!=6 || (n.PhysicalAddress[0]&1) ||
           std::all_of(n.PhysicalAddress,n.PhysicalAddress+6,[](auto b){return b==0;}) ||
           n.State==NlnsUnreachable || n.State==NlnsIncomplete)continue;
        auto adapter=interfaces.find(n.InterfaceLuid.Value);
        if(adapter==interfaces.end())continue;
        const auto& iface=adapter->second;
        auto v4=n.Address.si_family==AF_INET;
        auto address=ip_text(n.Address.si_family,v4?static_cast<const void*>(&n.Address.Ipv4.sin_addr):
            static_cast<const void*>(&n.Address.Ipv6.sin6_addr));
        if(address.empty())continue;
        ULONG scope=v4?0:n.Address.Ipv6.sin6_scope_id;
        auto ports=connections.remote_ports.find({address,scope});
        std::wstring known;
        if(ports!=connections.remote_ports.end())for(auto port:ports->second){
            if(!known.empty())known+=L", ";
            known+=service_label(port);
        }
        bool router=n.IsRouter || gateways.contains({n.InterfaceIndex,address});
        if(scope)address+=L"%"+std::to_wstring(scope);
        std::wstring id=router?L"Brama / router":(n.PhysicalAddress[0]&2)?L"MAC lokalny":L"Sąsiad";
        auto vendor=registry.vendor({n.PhysicalAddress,n.PhysicalAddressLength});
        const auto& name=field(vendor,"value");
        auto hostname=cached_hostname(n.Address);
        std::wstring producer=name.is_string()?from_utf8(name.get<std::string>()):L"Nieustalony";
        bool local_v6=!v4 && IN6_IS_ADDR_LINKLOCAL(&n.Address.Ipv6.sin6_addr);
        page.rows.push_back({{address,mac_text(n.PhysicalAddress),hostname.empty()?L"Brak w pamięci DNS":hostname,
            producer,id,known.empty()?L"—":known},std::wstring(L"Karta · ")+iface.Alias+
            (local_v6?L"\r\nIPv6 link-local · automatyczny adres tego łącza.":L"")+
            L"\r\nHostname pochodzi z lokalnej pamięci DNS. Producent pochodzi z prefiksu adresu MAC i bazy IEEE OUI." +
            L"\r\nWindows pamięta ten adres w tablicy sąsiadów. Wiek wpisu i aktywność urządzenia mogą się zmieniać."
            L"\r\nPorty z bieżących połączeń TCP. Nazwa usługi wynika z typowego użycia numeru portu."
            L"\r\nAdres sprzętowy jest odczytem lokalnym. Pomiary zapisywane na serwerze używają pseudonimów MAC.",{},{}});
    }
    if(page.rows.empty())page.rows.push_back({{L"Brak widocznych sąsiadów"},L"Windows nie ma dostępnych wpisów dla aktywnych kart.",{},{}});
    if(page.rows.size()==256)page.subtitle+=L" Pokazano pierwsze 256 wpisów.";
    return page;
}
}
