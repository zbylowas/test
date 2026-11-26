#include "inventory.hpp"
#include "queue.hpp"
#include <devguid.h>
#include <setupapi.h>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <set>
#include <thread>

namespace {
using Clock = std::chrono::steady_clock;

template <class T> struct MibFree {
    void operator()(T* table) const {
        if (table)
            FreeMibTable(table);
    }
};

std::string address(const SOCKADDR* sa) {
    if (!sa)
        return {};
    const void* data = nullptr;
    if (sa->sa_family == AF_INET)
        data = &reinterpret_cast<const sockaddr_in*>(sa)->sin_addr;
    if (sa->sa_family == AF_INET6)
        data = &reinterpret_cast<const sockaddr_in6*>(sa)->sin6_addr;
    char out[INET6_ADDRSTRLEN]{};
    if (!data || !InetNtopA(sa->sa_family, data, out, sizeof out))
        return {};
    return out;
}

std::wstring reg_string(HKEY key, const wchar_t* path, const wchar_t* name) {
    wchar_t value[512]{};
    DWORD size = sizeof value;
    if (RegGetValueW(key, path, name, RRF_RT_REG_SZ, nullptr, value, &size) != ERROR_SUCCESS)
        return {};
    return value;
}

std::map<std::string, std::string> driver_versions() {
    std::map<std::string, std::string> result;
    auto devices = SetupDiGetClassDevsW(&GUID_DEVCLASS_NET, nullptr, nullptr, DIGCF_PRESENT);
    if (devices == INVALID_HANDLE_VALUE)
        return result;
    for (DWORD i = 0;; ++i) {
        SP_DEVINFO_DATA device{};
        device.cbSize = sizeof device;
        if (!SetupDiEnumDeviceInfo(devices, i, &device))
            break;
        HKEY key = SetupDiOpenDevRegKey(devices, &device, DICS_FLAG_GLOBAL, 0, DIREG_DRV, KEY_QUERY_VALUE);
        if (key == INVALID_HANDLE_VALUE)
            continue;
        auto id = reg_string(key, nullptr, L"NetCfgInstanceId");
        auto version = reg_string(key, nullptr, L"DriverVersion");
        RegCloseKey(key);
        if (!id.empty() && !version.empty()) {
            CharUpperBuffW(id.data(), static_cast<DWORD>(id.size()));
            result[utf8(id)] = utf8(version);
        }
    }
    SetupDiDestroyDeviceInfoList(devices);
    return result;
}

Json system_snapshot() {
    SYSTEM_INFO info{};
    GetNativeSystemInfo(&info);
    MEMORYSTATUSEX memory{};
    memory.dwLength = sizeof memory;
    auto os = windows_version();
    auto cpu = reg_string(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
                          L"ProcessorNameString");
    auto memory_value =
        GlobalMemoryStatusEx(&memory)
            ? available({{"total_bytes", memory.ullTotalPhys}, {"available_bytes", memory.ullAvailPhys}})
            : unavailable("GlobalMemoryStatusEx:" + std::to_string(GetLastError()));
    auto processors = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
    std::string arch = "windows_machine_" + std::to_string(info.wProcessorArchitecture);
    if (info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
        arch = "x64";
    if (info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64)
        arch = "arm64";
    if (info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)
        arch = "x86";
    return {{"windows", os.empty() ? unavailable("RtlGetVersion") : available(os)},
            {"architecture", arch},
            {"logical_processors", processors ? processors : info.dwNumberOfProcessors},
            {"cpu_model", cpu.empty() ? unavailable("ProcessorNameString_missing") : available(utf8(cpu))},
            {"memory", memory_value}};
}

struct Counters {
    std::map<ULONG64, MIB_IF_ROW2> rows;
    DWORD error{};
    Clock::time_point time;
};
Counters sample_counters() {
    Counters result;
    MIB_IF_TABLE2* table{};
    result.error = GetIfTable2(&table);
    result.time = Clock::now();
    std::unique_ptr<MIB_IF_TABLE2, MibFree<MIB_IF_TABLE2>> hold(table);
    if (!result.error && table)
        for (ULONG i = 0; i < table->NumEntries; ++i)
            result.rows.emplace(table->Table[i].InterfaceLuid.Value, table->Table[i]);
    return result;
}

void set_counters(Json& out, ULONG64 id, const Counters& before, const Counters& after) {
    auto it = after.rows.find(id);
    if (it == after.rows.end()) {
        auto missing =
            unavailable("GetIfTable2:" + std::to_string(after.error ? after.error : ERROR_NOT_FOUND));
        for (auto name : {"link", "counters", "traffic"})
            out[name] = missing;
        return;
    }
    const auto& r = it->second;
    out["link"] = r.OperStatus == IfOperStatusUp && r.ReceiveLinkSpeed && r.TransmitLinkSpeed &&
                          r.ReceiveLinkSpeed != UINT64_MAX && r.TransmitLinkSpeed != UINT64_MAX
                      ? available({{"rx_bps", r.ReceiveLinkSpeed}, {"tx_bps", r.TransmitLinkSpeed}})
                      : unavailable("link_down_or_speed_unknown");
    out["counters"] = available({{"rx_errors", r.InErrors},
                                 {"tx_errors", r.OutErrors},
                                 {"rx_discards", r.InDiscards},
                                 {"tx_discards", r.OutDiscards},
                                 {"rx_bytes", r.InOctets},
                                 {"tx_bytes", r.OutOctets}});
    auto old = before.rows.find(id);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(after.time - before.time).count();
    if (old == before.rows.end() || r.OperStatus != IfOperStatusUp ||
        old->second.OperStatus != IfOperStatusUp || old->second.InOctets > r.InOctets ||
        old->second.OutOctets > r.OutOctets || ms <= 0) {
        out["traffic"] = unavailable("inactive_or_incomparable_counters");
        return;
    }
    const auto rx = (r.InOctets - old->second.InOctets) * 8000.0 / ms;
    const auto tx = (r.OutOctets - old->second.OutOctets) * 8000.0 / ms;
    const bool known = out["link"]["status"] == "ok";
    out["traffic"] = available({{"interval_ms", ms},
                                {"rx_bps", rx},
                                {"tx_bps", tx},
                                {"rx_utilization_pct", known ? available(rx * 100.0 / r.ReceiveLinkSpeed)
                                                             : unavailable("link_speed_unknown")},
                                {"tx_utilization_pct", known ? available(tx * 100.0 / r.TransmitLinkSpeed)
                                                             : unavailable("link_speed_unknown")}});
}

template <class T> Json ip_list(T* head) {
    Json rows = Json::array();
    size_t total = 0;
    for (auto* p = head; p; p = p->Next) {
        auto ip = address(p->Address.lpSockaddr);
        if (!ip.empty()) {
            if (++total <= 16)
                rows.push_back(ip);
        }
    }
    return limited(std::move(rows), total);
}

void interfaces(Json& result, const Bytes& key, const Counters& before, const Counters& after) {
    ULONG length = 15000;
    Bytes buffer(length);
    ULONG code = ERROR_BUFFER_OVERFLOW;
    for (int retry = 0; retry < 4 && code == ERROR_BUFFER_OVERFLOW; ++retry) {
        buffer.resize(length);
        code = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_INCLUDE_PREFIX, nullptr,
                                    reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()), &length);
    }
    if (code != NO_ERROR) {
        result["interfaces"] = result["duplicate_addresses"] =
            unavailable("GetAdaptersAddresses:" + std::to_string(code));
        return;
    }
    auto drivers = driver_versions();
    Json rows = Json::array(), duplicates = Json::array();
    size_t total = 0, duplicate_count = 0;
    for (auto* a = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()); a; a = a->Next) {
        Json ips = Json::array();
        size_t ip_count = 0;
        for (auto* u = a->FirstUnicastAddress; u; u = u->Next) {
            auto ip = address(u->Address.lpSockaddr);
            if (ip.empty())
                continue;
            if (++ip_count <= 32)
                ips.push_back(
                    {{"ip", ip}, {"prefix_length", u->OnLinkPrefixLength}, {"dad_state", u->DadState}});
            if (u->DadState == IpDadStateDuplicate && ++duplicate_count <= 128)
                duplicates.push_back({{"index", a->IfIndex}, {"ip", ip}});
        }
        if (++total > 32)
            continue;
        std::string id = a->AdapterName;
        CharUpperBuffA(id.data(), static_cast<DWORD>(id.size()));
        auto mac = mac_id({a->PhysicalAddress, a->PhysicalAddressLength}, key);
        Json row = {{"id", id},
                    {"index", a->IfIndex ? a->IfIndex : a->Ipv6IfIndex},
                    {"model", a->Description && *a->Description ? available(utf8(a->Description))
                                                                : unavailable("adapter_description_missing")},
                    {"type", a->IfType},
                    {"oper_status", a->OperStatus},
                    {"mtu", a->Mtu},
                    {"unicast", limited(std::move(ips), ip_count)},
                    {"gateways", ip_list(a->FirstGatewayAddress)},
                    {"dns", ip_list(a->FirstDnsServerAddress)},
                    {"mac_id", mac.empty() ? unavailable("no_unicast_mac48") : available(mac)},
                    {"driver", drivers.contains(id) ? available(drivers.at(id))
                                                    : unavailable("driver_version_unavailable")}};
        set_counters(row, a->Luid.Value, before, after);
        rows.push_back(std::move(row));
    }
    result["interfaces"] = limited(std::move(rows), total);
    result["duplicate_addresses"] = limited(std::move(duplicates), duplicate_count);
}

Json routes() {
    MIB_IPFORWARD_TABLE2* table{};
    auto rc = GetIpForwardTable2(AF_UNSPEC, &table);
    std::unique_ptr<MIB_IPFORWARD_TABLE2, MibFree<MIB_IPFORWARD_TABLE2>> hold(table);
    if (rc)
        return unavailable("GetIpForwardTable2:" + std::to_string(rc));
    Json rows = Json::array();
    for (ULONG i = 0; i < std::min<ULONG>(128, table->NumEntries); ++i) {
        const auto& r = table->Table[i];
        rows.push_back({{"index", r.InterfaceIndex},
                        {"prefix", address(reinterpret_cast<const SOCKADDR*>(&r.DestinationPrefix.Prefix))},
                        {"prefix_length", r.DestinationPrefix.PrefixLength},
                        {"next_hop", address(reinterpret_cast<const SOCKADDR*>(&r.NextHop))},
                        {"metric", r.Metric}});
    }
    return limited(std::move(rows), table->NumEntries);
}

void neighbors(Json& doc, const Bytes& key) {
    MIB_IPNET_TABLE2* table{};
    auto rc = GetIpNetTable2(AF_UNSPEC, &table);
    std::unique_ptr<MIB_IPNET_TABLE2, MibFree<MIB_IPNET_TABLE2>> hold(table);
    if (rc) {
        doc["neighbors"] = doc["unique_neighbor_macs"] = unavailable("GetIpNetTable2:" + std::to_string(rc));
        return;
    }
    const auto registry=read_oui_registry();
    Json rows = Json::array();
    std::set<std::string> unique;
    size_t total = 0;
    for (ULONG i = 0; i < table->NumEntries; ++i) {
        const auto& r = table->Table[i];
        if (r.State == NlnsUnreachable || r.State == NlnsIncomplete)
            continue;
        auto id = mac_id({r.PhysicalAddress, r.PhysicalAddressLength}, key);
        if (id.empty())
            continue;
        unique.insert(id);
        if (++total > 128)
            continue;
        auto manufacturer=registry.vendor({r.PhysicalAddress,r.PhysicalAddressLength});
        rows.push_back({{"index", r.InterfaceIndex},
                        {"ip", address(reinterpret_cast<const SOCKADDR*>(&r.Address))},
                        {"state", r.State},
                        {"mac_id", available(id)},
                        {"vendor", manufacturer}});
    }
    doc["neighbors"] = limited(std::move(rows), total);
    doc["unique_neighbor_macs"] = available(unique.size());
}
} // namespace

OuiRegistry read_oui_registry(){
    OuiRegistry result;
    std::ifstream input;
    auto path=environment(L"VIPNET_OUI_FILE");
    if(!path.empty())input.open(std::filesystem::path(path),std::ios::binary);
    result.loaded=input.is_open();
    std::string line;
    while(std::getline(input,line)){
        if(line.size()>7 && line.size()<=400 && line[6]=='\t')
            result.entries.emplace(line.substr(0,6),line.substr(7));
    }
    return result;
}
Json OuiRegistry::vendor(std::span<const unsigned char> address) const {
    if(address.size()!=6)return unavailable("invalid_hardware_address");
    if(address.front()&2)return unavailable("locally_administered_address");
    char prefix[7]{};
    std::snprintf(prefix,sizeof prefix,"%02X%02X%02X",address[0],address[1],address[2]);
    if(auto match=entries.find(prefix);match!=entries.end())return available(match->second);
    return unavailable(loaded?"oui_unknown":"oui_registry_missing");
}

Json collect_inventory(const Bytes& key) {
    Json doc = {{"captured_at", utc_now()}, {"system", system_snapshot()}};
    auto before = sample_counters();
    doc["wifi"] = wifi_snapshot(key);
    doc["routes"] = routes();
    neighbors(doc, key);
    std::this_thread::sleep_until(before.time + std::chrono::milliseconds(500));
    auto after = sample_counters();
    interfaces(doc, key, before, after);
    doc["finished_at"] = utc_now();
    return doc;
}
