#pragma once
#include "icmp.hpp"
#include <nlohmann/json.hpp>
#include <span>
#include <map>
#include <vector>

using Json = nlohmann::json;
using Bytes = std::vector<unsigned char>;

Json available(Json value);
Json unavailable(std::string reason);
Json limited(Json rows, size_t total);
std::string utf8(std::wstring_view value);
std::string windows_version();
std::string mac_id(std::span<const unsigned char> address, const Bytes& key);
Json wifi_snapshot(const Bytes& key);
struct OuiRegistry {
    std::map<std::string,std::string> entries;
    bool loaded{};
    Json vendor(std::span<const unsigned char> address) const;
};
OuiRegistry read_oui_registry();
Json collect_inventory(const Bytes& key);
