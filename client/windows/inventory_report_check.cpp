#include "inventory_report.hpp"
#include <iostream>
#include <stdexcept>

static void contains(const std::string& text, const std::string& expected) {
    if (text.find(expected) == std::string::npos) throw std::runtime_error("missing: " + expected);
}

int main() {
    contains(inventory_report(nullptr,Json::object()),"brak inwentaryzacji");
    const Json address = {{"ip","192.0.2.4"},{"prefix_length",24}};
    const Json card = {{"type",71},{"index",8},{"mtu",1500},{"oper_status",1},
                       {"model",available("Karta testowa")},{"unicast",available(Json::array({address}))}};
    Json inv = {{"interfaces",available(Json::array({card}))},{"unique_neighbor_macs",available(3)},
                {"wifi",unavailable("wlan_unavailable")}};
    const Json row = {{"index",8},{"mac_id",available("identifier_1")},{"vendor",available("Test OUI")}};
    Json other = row; other["index"] = 9; other["mac_id"] = available("identifier_2");
    inv["neighbors"] = {{"status","partial"},{"value",Json::array({row,row,other})},{"total",4},{"reason","row_limit"}};
    const Json transfer = {{"reservation_local_ip",available("192.0.2.4")}};
    // Reading older reports must never choose a card by its current link status.
    contains(inventory_report(inv,Json::object()),"Typ połączenia przy rezerwacji HTTPS   brak w zapisie");
    auto report = inventory_report(inv,transfer);
    contains(report,"Wi-Fi · Karta testowa");
    contains(report,"Sąsiedzi na karcie pomiarowej   co najmniej 1 · rozpoznani producenci: Test OUI");
    contains(report,"Sąsiedzi widoczni dla Windows   3");
    contains(report,"niedostępne (wlan_unavailable)");
    inv["interfaces"]["value"].push_back(card);
    contains(inventory_report(inv,transfer),"niejednoznaczne dopasowanie adresu");
    std::cout << "Report rendering passed for current, legacy, partial and ambiguous measurements\n";
}
