#include "inventory_report.hpp"
#include "reader_report.hpp"
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
    Json packet = {{"at","2026-11-25T00:00:00Z"},{"status","echo_reply"},{"responder","192.0.2.1"},{"rtt_ms",0},{"native_code",0}};
    Json host = {{"target","192.0.2.1"},{"reason",nullptr},{"samples",Json::array({packet})}};
    Json raw = {{"error",nullptr},{"peer","192.0.2.1"},{"host_pings",{{"gateway",host},{"node",host}}}};
    Json data = {{"throughput",raw},{"synchronized",false},{"mtr_samples",Json::array()}};
    contains(reader_report(data),"średnio 0 ms, odpowiedzi 1 z 1");
    data["throughput"]["host_pings"]["node"]["samples"][0]["status"]="unavailable";
    contains(reader_report(data),"Liczba prób, których Windows nie mógł wykonać: 1");
    data["throughput"].erase("host_pings");
    contains(reader_report(data),"nie zawiera oddzielnych pingów");
    for (int i=1;i<=5;++i) for (int ttl=1;ttl<=3;++ttl) {
        bool timeout=i<=2 && ttl>=2;
        std::string responder=ttl==3?"192.0.2.1":"192.0.2.2";
        data["mtr_samples"].push_back({{"phase","baseline"},{"target","192.0.2.1"},{"protocol","icmp"},
            {"attempt",i},{"ttl",ttl},{"status",timeout?"timeout":ttl==3?"echo_reply":"ttl_expired"},
            {"responder",timeout?Json(nullptr):Json(responder)}});
    }
    contains(reader_report(data),"od etapu 2 aż do serwera");
    data["mtr_samples"].back()["status"]="unavailable";
    if (reader_report(data).find("od etapu 2 aż do serwera")!=std::string::npos)
        throw std::runtime_error("local API error was presented as network loss");
    std::cout << "Report rendering passed for current, legacy, partial and ambiguous measurements\n";
}
