#pragma once
#include "reader_report.hpp"
#include <array>
#include <optional>
#include <vector>

namespace summary {
enum class Tone { neutral, observed, warning, problem };
struct Fact {
    std::wstring label, value, detail;
    Tone tone=Tone::neutral;
};
struct Point { double seconds,mbps; };
enum Check : size_t {
    check_computer, check_connection, check_lan, check_operator, check_dns, check_ipv4, check_ipv6,
    check_stability, check_latency, check_count
};
struct Ipv6Address {
    std::wstring address, label, detail;
};
struct Snapshot {
    std::array<Fact,7> metrics;
    std::array<Fact,check_count> checks;
    std::array<std::vector<Point>,2> lines;
    std::array<std::optional<double>,2> speed_mbps;
    std::wstring last, finding, action, finding_detail, save_status;
    Tone finding_tone=Tone::neutral;
    bool recorded{}, partial{}, synced{};
};

const Json& field(const Json& object,const char* key);
std::optional<double> speed(const Json& transfer,const char* direction);
std::optional<double> typical_delay(const Json& samples);
const Json* used_adapter(const Json& inventory,const Json& transfer);
std::wstring number(double value);
std::wstring from_utf8(const std::string& text);
std::vector<Point> rates(const Json& counters);
bool link_local_v6(std::wstring_view address);
std::vector<Ipv6Address> ipv6_addresses(const Json& report,const Json* adapter);
std::vector<std::wstring> display_dns(const Json& adapter);
Snapshot read(const Json& report);
}
