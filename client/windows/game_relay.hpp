#pragma once
#include <chrono>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

struct GameRelay {
    std::string host, utc;
};

std::optional<GameRelay> recent_roblox_relay(const std::filesystem::path& logs,
                                            std::chrono::sys_seconds now);

std::optional<GameRelay> roblox_relay_line(std::string_view line, std::chrono::sys_seconds now);
std::optional<std::string> league_match_address(std::string_view log);
std::optional<GameRelay> recent_league_match(const std::filesystem::path& logs, std::chrono::sys_seconds now);
