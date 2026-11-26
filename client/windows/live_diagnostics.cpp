#include "live_diagnostics.hpp"
#include "queue.hpp"
#include <tlhelp32.h>
#include <algorithm>
#include <map>
#include <set>
#include <memory>
#include <thread>

namespace summary {
namespace {
using Clock=std::chrono::steady_clock;
struct Owner {
    unsigned tcp{}, udp{};
};
struct SocketSnapshot {
    std::map<DWORD,Owner> owners;
    std::map<std::pair<std::wstring,ULONG>,std::set<unsigned>> remote_ports;
    unsigned tables{};
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
        ++result.owners[row.dwOwningPid].tcp;
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
        if(!raw.empty()){
            ++result.tables;
            if(family==AF_INET)tcp_rows(*reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(raw.data()),result);
            else tcp_rows(*reinterpret_cast<const MIB_TCP6TABLE_OWNER_PID*>(raw.data()),result);
        }
        raw.clear();
        load_table([family](void* data,DWORD* size){return GetExtendedUdpTable(data,size,FALSE,family,UDP_TABLE_OWNER_PID,0);},raw);
        if(raw.empty())continue;
        ++result.tables;
        if(family==AF_INET){
            auto& t=*reinterpret_cast<const MIB_UDPTABLE_OWNER_PID*>(raw.data());
            for(DWORD i=0;i<t.dwNumEntries;++i)++result.owners[t.table[i].dwOwningPid].udp;
        }else{
            auto& t=*reinterpret_cast<const MIB_UDP6TABLE_OWNER_PID*>(raw.data());
            for(DWORD i=0;i<t.dwNumEntries;++i)++result.owners[t.table[i].dwOwningPid].udp;
        }
    }
    return result;
}
unsigned long long ticks(FILETIME value){
    return (static_cast<unsigned long long>(value.dwHighDateTime)<<32)|value.dwLowDateTime;
}
struct Process {
    std::wstring name;
    unsigned long long created{}, cpu{}, read{}, written{};
    bool cpu_ok{}, io_ok{};
};
std::map<DWORD,Process> processes(){
    std::map<DWORD,Process> out;
    HANDLE list=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if(list==INVALID_HANDLE_VALUE)return out;
    PROCESSENTRY32W p{};p.dwSize=sizeof p;
    if(Process32FirstW(list,&p))do{
        if(!p.th32ProcessID)continue;
        Process process;process.name=p.szExeFile;
        if(auto handle=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,p.th32ProcessID)){
            FILETIME created{},exited{},kernel{},user{};
            process.cpu_ok=GetProcessTimes(handle,&created,&exited,&kernel,&user)!=FALSE;
            process.created=ticks(created);process.cpu=ticks(kernel)+ticks(user);
            IO_COUNTERS io{};
            process.io_ok=GetProcessIoCounters(handle,&io)!=FALSE;
            process.read=io.ReadTransferCount;process.written=io.WriteTransferCount;
            CloseHandle(handle);
        }
        out.emplace(p.th32ProcessID,std::move(process));
    }while(Process32NextW(list,&p));
    CloseHandle(list);
    return out;
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
std::wstring report_time(){
    return L"Odczyt "+from_utf8(utc_now())+L" · ";
}
}
DetailPage live_computer(const DetailPage& previous) {
    auto started=Clock::now();
    const auto before=processes();
    const auto before_links=links();
    std::this_thread::sleep_until(started+std::chrono::milliseconds(600));
    const auto after=processes();
    const auto after_links=links();
    const double elapsed=std::chrono::duration<double>(Clock::now()-started).count();
    const double capacity=elapsed*1e7*std::max<DWORD>(1,GetActiveProcessorCount(ALL_PROCESSOR_GROUPS));
    const auto connections=sockets();
    DetailPage page{report_time()+L"Procesy, gniazda sieciowe i obciążenie. Dwuklik otwiera szczegóły.",
        {{L"Proces / parametr",210},{L"PID / wartość",144},{L"TCP",64},{L"UDP",64},{L"CPU",83},{L"Odczyt / zapis",150}},{}};
    struct Activity { double cpu; unsigned sockets; DetailRow row; };
    std::vector<Activity> activities;
    size_t hidden=0;
    for(const auto& [pid,p]:after){
        auto first=before.find(pid);
        const auto owner=connections.owners.find(pid);
        auto counts=owner==connections.owners.end()?Owner{}:owner->second;
        bool same=first!=before.end() && p.cpu_ok && first->second.cpu_ok && p.created==first->second.created && p.cpu>=first->second.cpu;
        double cpu=same?100.0*(p.cpu-first->second.cpu)/capacity:0.0;
        bool io_ok=same && p.io_ok && first->second.io_ok && p.read>=first->second.read && p.written>=first->second.written;
        if(!same)++hidden;
        if(!counts.tcp && !counts.udp && cpu<0.2 && !io_ok)continue;
        if(!counts.tcp && !counts.udp && cpu<0.2 && io_ok &&
            first->second.read==p.read && first->second.written==p.written)continue;
        auto io=io_ok?number((p.read-first->second.read)/(elapsed*1024.0))+L" / "+
              number((p.written-first->second.written)/(elapsed*1024.0))+L" KiB/s":L"—";
        DetailRow row;
        row.cells={p.name,std::to_wstring(pid),connections.tables?std::to_wstring(counts.tcp):L"—",
            connections.tables?std::to_wstring(counts.udp):L"—",same?number(cpu)+L" %":L"—",io};
        row.detail=L"TCP · zestawione połączenia. UDP · lokalne gniazda. Odczyt i zapis to liczniki I/O Windows. Mogą obejmować dysk i urządzenia. "
            L"Obecność gniazd wskazuje aplikacje do sprawdzenia. Z tego odczytu nie można ustalić Mb/s procesu ani udowodnić blokowania transferu.";
        if(!same)row.detail+=L" Windows nie udostępnił porównywalnych liczników CPU dla tego procesu.";
        activities.push_back({cpu,counts.tcp+counts.udp,std::move(row)});
    }
    std::stable_sort(activities.begin(),activities.end(),[](const auto& a,const auto& b){
        if(a.cpu!=b.cpu)return a.cpu>b.cpu;
        return a.sockets>b.sockets;
    });
    MEMORYSTATUSEX memory{};memory.dwLength=sizeof memory;
    page.rows.push_back({{L"RAM teraz",GlobalMemoryStatusEx(&memory)?std::to_wstring(memory.dwMemoryLoad)+L" % zajęte":L"Brak odczytu"},
        L"Procent zajętej pamięci fizycznej zgłoszony przez Windows.",{},{}});
    page.rows.push_back({{L"Tablice gniazd",std::to_wstring(connections.tables)+L" / 4"},
        L"Tabele TCP i UDP dla IPv4 i IPv6. Częściowy odczyt może pominąć niektóre gniazda.",{},{}});
    page.rows.push_back({{L"Aktywne procesy",std::to_wstring(activities.size())},
        L"Wartości zmierzone przez "+number(elapsed)+L" s. Pokazano do 100 aktywnych procesów. Nieporównywalny odczyt CPU: "+std::to_wstring(hidden)+L" procesów.",{},{}});
    for(const auto& [id,iface]:after_links){
        auto prior=before_links.find(id);
        if(prior==before_links.end() || iface.InOctets<prior->second.InOctets || iface.OutOctets<prior->second.OutOctets)continue;
        auto receive=number((iface.InOctets-prior->second.InOctets)*8.0/(elapsed*1e6));
        auto sent=number((iface.OutOctets-prior->second.OutOctets)*8.0/(elapsed*1e6));
        page.rows.push_back({{std::wstring(L"Ruch · ")+iface.Alias,receive+L" / "+sent+L" Mb/s"},
            L"Średni ruch pobierania i wysyłania tej karty podczas odczytu. Obejmuje ruch wszystkich procesów i komunikację lokalną.",{},{}});
    }
    if(after.empty())page.rows.push_back({{L"Procesy",L"Brak odczytu"},L"Windows nie udostępnił listy procesów.",{},{}});
    for(size_t i=0;i<std::min<size_t>(100,activities.size());++i)page.rows.push_back(std::move(activities[i].row));
    for(const auto& row:previous.rows)page.rows.push_back(row);
    return page;
}
DetailPage live_lan(){
    DetailPage page{report_time()+L"Urządzenia znane karcie i połączenia TCP widoczne na tym komputerze.",
        {{L"Adres IP",190},{L"Adres MAC",150},{L"Urządzenie",190},{L"Porty zdalne TCP",150}},{}};
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
        if(name.is_string())id+=L" · "+from_utf8(name.get<std::string>());
        page.rows.push_back({{address,mac_text(n.PhysicalAddress),id,
            known.empty()?L"—":known},std::wstring(L"Karta · ")+iface.Alias+
            L"\r\nWindows pamięta ten adres w tablicy sąsiadów. Wiek wpisu i aktywność urządzenia mogą się zmieniać."
            L"\r\nPorty z bieżących połączeń TCP. Nazwa usługi wynika z typowego użycia numeru portu."
            L"\r\nAdres sprzętowy jest odczytem lokalnym. Pomiary zapisywane na serwerze używają pseudonimów MAC.",{},{}});
    }
    if(page.rows.empty())page.rows.push_back({{L"Brak widocznych sąsiadów"},L"Windows nie ma dostępnych wpisów dla aktywnych kart.",{},{}});
    if(page.rows.size()==256)page.subtitle+=L" Pokazano pierwsze 256 wpisów.";
    return page;
}
}
