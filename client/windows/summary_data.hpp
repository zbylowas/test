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
struct Snapshot {
    std::array<Fact,7> metrics;
    std::array<Fact,10> checks;
    std::array<std::vector<Point>,2> lines;
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
std::vector<std::wstring> display_dns(const Json& adapter);
Snapshot read(const Json& report);
}
