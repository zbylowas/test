#include "inventory.hpp"
#include <wlanapi.h>
#include <objbase.h>
#include <memory>

namespace {
struct WlanHandle {
    HANDLE value{};
    ~WlanHandle() {
        if (value)
            WlanCloseHandle(value, nullptr);
    }
};
struct FreeWlan {
    void operator()(void* data) const { WlanFreeMemory(data); }
};
template <class T, class Format>
Json query(HANDLE handle, const GUID& id, WLAN_INTF_OPCODE opcode, Format format) {
    DWORD size{};
    void* raw{};
    auto rc = WlanQueryInterface(handle, &id, opcode, nullptr, &size, &raw, nullptr);
    std::unique_ptr<void, FreeWlan> hold(raw);
    if (rc != ERROR_SUCCESS)
        return unavailable("WlanQueryInterface:" + std::to_string(rc));
    if (!raw || size < sizeof(T))
        return unavailable("short_wlan_result");
    return available(format(*static_cast<const T*>(raw)));
}
} // namespace

Json wifi_snapshot(const Bytes& key) {
    WlanHandle handle;
    DWORD version{};
    auto rc = WlanOpenHandle(2, nullptr, &version, &handle.value);
    if (rc)
        return unavailable("WlanOpenHandle:" + std::to_string(rc));
    WLAN_INTERFACE_INFO_LIST* list{};
    rc = WlanEnumInterfaces(handle.value, nullptr, &list);
    std::unique_ptr<WLAN_INTERFACE_INFO_LIST, FreeWlan> hold(list);
    if (rc || !list)
        return unavailable("WlanEnumInterfaces:" + std::to_string(rc));
    Json rows = Json::array();
    for (DWORD i = 0; i < std::min<DWORD>(16, list->dwNumberOfItems); ++i) {
        const auto& item = list->InterfaceInfo[i];
        wchar_t id[40]{};
        StringFromGUID2(item.InterfaceGuid, id, 40);
        Json row = {{"id", utf8(id)}, {"state", item.isState}};
        row["connection"] = query<WLAN_CONNECTION_ATTRIBUTES>(
            handle.value, item.InterfaceGuid, wlan_intf_opcode_current_connection, [&](const auto& v) {
                const auto& a = v.wlanAssociationAttributes;
                auto hash = mac_id(a.dot11Bssid, key);
                return Json{{"bssid_id", hash.empty() ? unavailable("missing_bssid") : available(hash)},
                            {"phy", a.dot11PhyType},
                            {"signal_pct", a.wlanSignalQuality},
                            {"rx_kbps", a.ulRxRate},
                            {"tx_kbps", a.ulTxRate}};
            });
        row["rssi_dbm"] =
            query<LONG>(handle.value, item.InterfaceGuid, wlan_intf_opcode_rssi, [](auto n) { return n; });
        row["channel"] = query<ULONG>(handle.value, item.InterfaceGuid, wlan_intf_opcode_channel_number,
                                      [](auto n) { return n; });
        rows.push_back(std::move(row));
    }
    return limited(std::move(rows), list->dwNumberOfItems);
}
