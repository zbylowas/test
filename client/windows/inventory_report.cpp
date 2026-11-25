#include "inventory_report.hpp"
#include <iomanip>
#include <set>
#include <sstream>

namespace {
const Json& field(const Json& obj, const char* key) {
    static const Json missing;
    auto it = obj.find(key);
    return it == obj.end() ? missing : *it;
}

std::string reason(const Json& entry) {
    const auto& code = field(entry, "reason");
    return code.is_string() ? "niedostępne (" + code.get<std::string>() + ")" : "brak w zapisie";
}

std::string scalar(const Json& value, const Json& entry, double divisor = 1, const char* unit = "") {
    if (value.is_string()) return value.get<std::string>();
    if (!value.is_number()) return reason(entry);
    std::ostringstream text;
    if (divisor == 1 && value.is_number_integer()) text << value.dump();
    else text << std::fixed << std::setprecision(2) << value.get<double>() / divisor;
    return text.str() + unit;
}

std::string reading(const Json& entry, const char* key = nullptr, double divisor = 1, const char* unit = "") {
    const auto& value = field(entry, "value");
    return scalar(key ? field(value, key) : value, entry, divisor, unit);
}

std::string medium(int type) {
    switch (type) {
        case 6: return "Ethernet";
        case 71: return "Wi-Fi";
        case 23: return "PPP";
        case 24: return "Loopback";
        case 131: return "Tunel";
        case 243: case 244: return "Sieć komórkowa";
        default: return "Typ interfejsu Windows " + std::to_string(type);
    }
}

std::string phy(const Json& connection) {
    const auto& value = field(field(connection, "value"), "phy");
    if (!value.is_number_integer()) return reason(connection);
    switch (value.get<int>()) {
        case 4: return "802.11a"; case 5: return "802.11b"; case 6: return "802.11g";
        case 7: return "802.11n"; case 8: return "802.11ac"; case 9: return "802.11ad";
        case 10: return "802.11ax"; case 11: return "802.11be";
        default: return "PHY " + value.dump();
    }
}

std::string addresses(const Json& entry) {
    const auto& rows = field(entry, "value");
    if (!rows.is_array()) return reason(entry);
    std::string text;
    for (const auto& address : rows) {
        if (!text.empty()) text += ", ";
        text += address.get<std::string>();
    }
    if (text.empty()) text = "brak wpisów";
    if (entry.value("status", "") == "partial") text += " (lista częściowa)";
    return text;
}

std::string table_count(const Json& entry) {
    const auto& rows = field(entry, "value");
    if (!rows.is_array()) return reason(entry);
    return std::to_string(rows.size()) + (entry.value("status","") == "partial" ? " (wynik częściowy)" : "");
}

std::string interface_neighbors(const Json& table, const Json& index) {
    const auto& rows = field(table,"value");
    if (!rows.is_array()) return reason(table);
    std::set<std::string> ids, vendors;
    for (const auto& row : rows) {
        if (field(row,"index") != index) continue;
        const auto& mac = field(field(row,"mac_id"),"value");
        const auto& vendor = field(field(row,"vendor"),"value");
        if (mac.is_string()) ids.insert(mac.get<std::string>());
        if (vendor.is_string()) vendors.insert(vendor.get<std::string>());
    }
    std::string text = table.value("status","") == "partial" ? "co najmniej " : "";
    text += std::to_string(ids.size());
    if (!vendors.empty()) {
        text += " · rozpoznani producenci: ";
        for (const auto& vendor : vendors) {
            if (vendor != *vendors.begin()) text += ", ";
            text += vendor;
        }
    }
    return text;
}
}

std::string inventory_report(const Json& inventory, const Json& throughput) {
    if (!inventory.is_object()) return "Komputer i sieć lokalna · brak inwentaryzacji w tej sesji\r\n";
    const auto& table = field(inventory, "interfaces");
    const auto& interfaces = field(table, "value");
    const auto& endpoint = field(throughput, "reservation_local_ip");
    const auto& ip = field(endpoint, "value");
    const Json* matched = nullptr;
    size_t matches = 0;
    for (const auto& nic : interfaces) {
        for (const auto& addr : field(field(nic,"unicast"),"value"))
            if (ip.is_string() && field(addr,"ip") == ip) { matched = &nic; ++matches; break; }
    }
    std::ostringstream out;
    out << "Typ połączenia przy rezerwacji HTTPS   ";
    if (matches == 1) {
        out << medium(matched->at("type")) << " · " << reading(field(*matched,"model"))
            << "\r\nSąsiedzi na karcie pomiarowej   " << interface_neighbors(field(inventory,"neighbors"),matched->at("index"));
    }
    else if (!ip.is_string()) out << reason(endpoint);
    else out << (matches ? "niejednoznaczne dopasowanie adresu" : "brak karty z adresem połączenia w odczycie Windows");
    out << "\r\nSąsiedzi widoczni dla Windows   " << reading(field(inventory,"unique_neighbor_macs"))
        << "\r\nLicznik obejmuje unikalne adresy MAC pamiętane przez ARP/IPv6 na interfejsach komputera. "
           "Może obejmować routery, telefony i urządzenia wirtualne.\r\n";
    const auto& system = field(inventory, "system");
    out << "Procesor   " << reading(field(system,"cpu_model")) << " · procesory logiczne: "
        << scalar(field(system,"logical_processors"),system) << "\r\nRAM   "
        << reading(field(system,"memory"),"total_bytes",1073741824," GiB") << " · dostępne: "
        << reading(field(system,"memory"),"available_bytes",1073741824," GiB") << "\r\n";
    out << "Aktywne interfejsy Windows\r\n";
    size_t active = 0;
    for (const auto& nic : interfaces) {
        if (nic.at("oper_status") != 1) continue;
        ++active;
        const auto& link = field(nic,"link");
        const auto& counters = field(nic,"counters");
        out << "  " << medium(nic.at("type")) << " · " << reading(field(nic,"model"))
            << " · sterownik " << reading(field(nic,"driver")) << " · MTU " << nic.at("mtu") << "\r\n"
            << "  Prędkość łącza RX / TX: " << reading(link,"rx_bps",1e6," Mb/s") << " / " << reading(link,"tx_bps",1e6," Mb/s")
            << " · ruch przed testem RX / TX: " << reading(field(nic,"traffic"),"rx_bps",1e6," Mb/s")
            << " / " << reading(field(nic,"traffic"),"tx_bps",1e6," Mb/s") << "\r\n"
            << "  Błędy RX / TX: " << reading(counters,"rx_errors") << " / " << reading(counters,"tx_errors")
            << " · odrzucenia RX / TX: " << reading(counters,"rx_discards") << " / " << reading(counters,"tx_discards") << "\r\n"
            << "  Bramy: " << addresses(field(nic,"gateways")) << " · DNS: " << addresses(field(nic,"dns")) << "\r\n";
        const auto& unicast = field(nic,"unicast");
        out << "  Adresy IP:";
        if (!field(unicast,"value").is_array()) out << " " << reason(unicast);
        else if (unicast.at("value").empty()) out << " brak wpisów";
        else for (const auto& addr : unicast.at("value")) out << " " << addr.at("ip").get<std::string>() << "/" << addr.at("prefix_length");
        if (unicast.value("status","") == "partial") out << " (lista częściowa)";
        out << "\r\n";
    }
    if (!active) out << "  " << (interfaces.is_array() ? "brak aktywnych w zapisanej liście" : reason(table)) << "\r\n";
    if (table.is_object() && table.value("status","") == "partial") out << "  Lista kart częściowa.\r\n";
    const auto& wifi = field(inventory,"wifi");
    const auto& radios = field(wifi,"value");
    out << "Wi-Fi";
    if (!radios.is_array()) out << "   " << reason(wifi);
    else if (radios.empty()) out << "   brak kart Wi-Fi w odczycie Windows";
    for (const auto& radio : radios) {
        const auto& connection = field(radio,"connection");
        out << "\r\n  " << phy(connection) << " · sygnał " << reading(connection,"signal_pct",1,"%")
            << " · RSSI " << reading(field(radio,"rssi_dbm"),nullptr,1," dBm")
            << " · kanał " << reading(field(radio,"channel"))
            << " · RX / TX: " << reading(connection,"rx_kbps",1000," Mb/s") << " / " << reading(connection,"tx_kbps",1000," Mb/s");
    }
    out << "\r\nAdresy uznane przez Windows za zduplikowane: " << table_count(field(inventory,"duplicate_addresses"))
        << " · zmiany MAC bramy: " << table_count(field(inventory,"gateway_changes")) << "\r\n";
    return out.str();
}
