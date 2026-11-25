#include "inventory.hpp"
#include <bcrypt.h>
#include <array>
#include <stdexcept>

Json available(Json value) { return {{"status", "ok"}, {"value", std::move(value)}}; }
Json unavailable(std::string reason) { return {{"status", "unavailable"}, {"reason", std::move(reason)}}; }
Json limited(Json rows, size_t total) {
    if (rows.size() == total)
        return available(std::move(rows));
    return {{"status", "partial"}, {"reason", "row_limit"}, {"total", total}, {"value", std::move(rows)}};
}

std::string utf8(std::wstring_view value) {
    if (value.empty())
        return {};
    const int count = static_cast<int>(value.size());
    int length =
        WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), count, nullptr, 0, nullptr, nullptr);
    if (length == 0)
        throw std::runtime_error("invalid Windows Unicode string");
    std::string out(length, '\0');
    if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), count, out.data(), length, nullptr,
                             nullptr))
        throw std::runtime_error("Unicode conversion failed");
    return out;
}

std::string windows_version() {
    using GetVersion = LONG(WINAPI*)(OSVERSIONINFOW*);
    const auto version_fn =
        reinterpret_cast<GetVersion>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion"));
    OSVERSIONINFOW v{};
    v.dwOSVersionInfoSize = sizeof(v);
    if (!version_fn || version_fn(&v) != 0)
        return {};
    return std::to_string(v.dwMajorVersion) + "." + std::to_string(v.dwMinorVersion) + "." +
           std::to_string(v.dwBuildNumber);
}

std::string mac_id(std::span<const unsigned char> address, const Bytes& key) {
    if (address.size() != 6 || (address[0] & 1) ||
        std::all_of(address.begin(), address.end(), [](auto b) { return b == 0; }))
        return {};
    BCRYPT_ALG_HANDLE alg{};
    if (!BCRYPT_SUCCESS(
            BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG)))
        throw std::runtime_error("HMAC provider unavailable");
    std::array<unsigned char, 32> digest{};
    auto result = BCryptHash(alg, const_cast<PUCHAR>(key.data()), static_cast<ULONG>(key.size()),
                             const_cast<PUCHAR>(address.data()), static_cast<ULONG>(address.size()),
                             digest.data(), static_cast<ULONG>(digest.size()));
    BCryptCloseAlgorithmProvider(alg, 0);
    if (!BCRYPT_SUCCESS(result))
        throw std::runtime_error("HMAC calculation failed");
    constexpr char hex[] = "0123456789abcdef";
    std::string out;
    for (auto byte : digest) {
        out += hex[byte >> 4];
        out += hex[byte & 15];
    }
    return out;
}
