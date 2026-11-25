#pragma once
#include <string>
#include <filesystem>

namespace updates {
struct Release {
    std::string version, sha256;
    unsigned long size{};
};
int finish_pending_update(unsigned long parent_pid);
void cleanup() noexcept;
Release verify(const std::string& manifest);
bool newer(const std::string& offered, const std::string& installed);
Release check(const std::wstring& origin);
void install(const Release& release, const std::wstring& origin);
void replace_verified(const Release& release, const std::string& bytes, const std::filesystem::path& target);
}
