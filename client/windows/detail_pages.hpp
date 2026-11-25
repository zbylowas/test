#pragma once
#include "summary_data.hpp"

namespace summary {
struct DetailRow {
    std::vector<std::wstring> cells;
    std::wstring detail;
    std::vector<std::optional<double>> points;
    std::wstring unit;
};
struct DetailPage {
    std::wstring subtitle;
    std::vector<std::pair<std::wstring,int>> columns;
    std::vector<DetailRow> rows;
};
DetailPage detail_page(int page,const Json& report,const Snapshot& snapshot);
DetailPage ping_page(const Json& samples);
DetailPage route_page(const Json& samples);
}
