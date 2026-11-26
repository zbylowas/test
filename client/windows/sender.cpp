#include "queue.hpp"
#include <winhttp.h>
#include <zlib.h>
#include <algorithm>
#include <cerrno>
#include <cwctype>
#include <limits>
#include <stdexcept>
#include <vector>

namespace {
struct Internet {
    HINTERNET handle{};
    ~Internet() { if (handle) WinHttpCloseHandle(handle); }
    operator HINTERNET() const { return handle; }
};

std::string gzip(const std::string& source) {
    z_stream stream{};
    if (deflateInit2(&stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15+16, 8, Z_DEFAULT_STRATEGY) != Z_OK)
        throw std::runtime_error("gzip initialization failed");
    struct End { z_stream& s; ~End() { deflateEnd(&s); } } guard{stream};
    std::string data(deflateBound(&stream, static_cast<uLong>(source.size())), '\0');
    stream.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(source.data()));
    stream.avail_in = static_cast<uInt>(source.size());
    stream.next_out = reinterpret_cast<Bytef*>(data.data());
    stream.avail_out = static_cast<uInt>(data.size());
    if (deflate(&stream,Z_FINISH) != Z_STREAM_END) throw std::runtime_error("gzip failed");
    data.resize(stream.total_out);
    return data;
}

unsigned retry_seconds(HINTERNET request) {
    wchar_t buffer[128]{};
    DWORD size = sizeof(buffer);
    if (!WinHttpQueryHeaders(request, WINHTTP_QUERY_RETRY_AFTER, nullptr, buffer, &size, nullptr)) return 0;
    wchar_t* end{};
    auto value = wcstoul(buffer, &end, 10);
    if (end != buffer && !*end) return value;
    SYSTEMTIME when{};
    FILETIME deadline{}, now{};
    if (!WinHttpTimeToSystemTime(buffer, &when) || !SystemTimeToFileTime(&when,&deadline)) return 0;
    GetSystemTimeAsFileTime(&now);
    auto ticks = [](FILETIME t) { return (static_cast<unsigned long long>(t.dwHighDateTime) << 32) | t.dwLowDateTime; };
    if (ticks(deadline) <= ticks(now)) return 0;
    return static_cast<unsigned>(std::min<unsigned long long>(UINT_MAX,(ticks(deadline)-ticks(now))/10000000+1));
}

Delivery failed() { return {-static_cast<int>(GetLastError()),0,{}}; }
}

Sender::Sender() {
    auto url = environment(L"VIPNET_API_ORIGIN");
    auto token = environment(L"VIPNET_TOKEN");
    if (url.empty() || token.empty()) throw std::runtime_error("set VIPNET_API_ORIGIN and VIPNET_TOKEN");
    URL_COMPONENTS c{};
    c.dwStructSize = sizeof(c);
    c.dwHostNameLength = c.dwUrlPathLength = c.dwExtraInfoLength = c.dwUserNameLength = c.dwPasswordLength = DWORD(-1);
    if (!WinHttpCrackUrl(url.c_str(), 0, 0, &c) || c.nScheme != INTERNET_SCHEME_HTTPS || !c.dwHostNameLength ||
        c.dwUserNameLength || c.dwPasswordLength || c.dwExtraInfoLength ||
        (c.dwUrlPathLength && std::wstring_view(c.lpszUrlPath,c.dwUrlPathLength) != L"/"))
        throw std::runtime_error("HTTPS origin required, without credentials, path or query");
    host_.assign(c.lpszHostName,c.dwHostNameLength);
    for (auto& ch : host_) {
        if (ch > 127) throw std::runtime_error("use ASCII or punycode hostname");
        ch = static_cast<wchar_t>(towlower(ch));
    }
    std::wstring_view secret(token);
    if (secret.size()<32 || secret.size()>256 ||
        std::any_of(secret.begin(),secret.end(),[](wchar_t ch){return ch<33 || ch>126;}))
        throw std::runtime_error("invalid bearer token");
    bearer_ = L"Authorization: Bearer " + std::wstring(secret) + L"\r\nContent-Type: application/json\r\n";
    port_ = c.nPort;
    origin = "https://";
    for (wchar_t ch : host_) origin += static_cast<char>(ch);
    origin += ":" + std::to_string(port_);
}

Delivery Sender::put(const std::string& path, const std::string& body, bool compress) const {
#ifdef VIPNET_LOOPBACK_RELAY
    constexpr DWORD proxy = WINHTTP_ACCESS_TYPE_NO_PROXY;
#else
    constexpr DWORD proxy = WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY;
#endif
    Internet session{WinHttpOpen(L"VIP-NET/1.1.1",proxy,nullptr,nullptr,0)};
    if (!session || !WinHttpSetTimeouts(session,3000,3000,5000,10000)) return failed();
    Internet connection{WinHttpConnect(session,host_.c_str(),port_,0)};
    if (!connection) return failed();
    std::wstring resource(path.begin(),path.end());
#ifdef VIPNET_LOOPBACK_RELAY
    // Separate acceptance executable. TLS to the private API is supplied by the loopback relay.
    if (host_ != L"127.0.0.1") throw std::runtime_error("fixture requires numeric loopback");
    constexpr DWORD flags = 0;
#else
    constexpr DWORD flags = WINHTTP_FLAG_SECURE;
#endif
    Internet req{WinHttpOpenRequest(connection,L"PUT",resource.c_str(),nullptr,nullptr,nullptr,flags)};
    if (!req) return failed();
    DWORD policy = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
    if (!WinHttpSetOption(req,WINHTTP_OPTION_REDIRECT_POLICY,&policy,sizeof(policy))) return failed();
    DWORD disable = WINHTTP_DISABLE_AUTHENTICATION | WINHTTP_DISABLE_COOKIES;
    if (!WinHttpSetOption(req,WINHTTP_OPTION_DISABLE_FEATURE,&disable,sizeof(disable))) return failed();
    auto payload = compress ? gzip(body) : body;
    auto headers = bearer_ + (compress ? L"Content-Encoding: gzip\r\n" : L"");
    DWORD size = static_cast<DWORD>(payload.size());
    if (!WinHttpSendRequest(req,headers.c_str(),DWORD(-1),payload.data(),size,size,0) ||
        !WinHttpReceiveResponse(req,nullptr)) return failed();
    DWORD status{}, bytes=sizeof(status);
    if (!WinHttpQueryHeaders(req,WINHTTP_QUERY_STATUS_CODE|WINHTTP_QUERY_FLAG_NUMBER,nullptr,&status,&bytes,nullptr))
        return failed();
    Delivery result{static_cast<int>(status),retry_seconds(req),{}};
    if (status == 200 || status == 201 || status == 202) {
        char buffer[1024];
        for (;;) {
            if (!WinHttpReadData(req,buffer,sizeof(buffer),&bytes)) return failed();
            if (!bytes) break;
            if (result.body.size()+bytes>4096) return {-ERROR_INVALID_DATA,0,{}};
            result.body.append(buffer,bytes);
        }
    }
    return result;
}
