#include "game_relay.hpp"
#include "icmp.hpp"
#include <algorithm>
#include <charconv>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <string_view>
#include <vector>

namespace {
using namespace std::chrono;

int decimal(std::string_view text) {
    int value{};
    auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
    return error == std::errc{} && end == text.data() + text.size() ? value : -1;
}

}

std::optional<GameRelay> roblox_relay_line(std::string_view line, sys_seconds now) {
    constexpr std::string_view marker = "[FLog::Network] UDMUX Address = ";
    auto pos = line.find(marker);
    if (pos == line.npos || pos < 24 || line[4]!='-' || line[7]!='-' || line[10]!='T' ||
        line[13]!=':' || line[16]!=':' || line.substr(19,1)!="." || line.substr(23,2)!="Z,") return {};
    int y=decimal(line.substr(0,4)), m=decimal(line.substr(5,2)), d=decimal(line.substr(8,2));
    int h=decimal(line.substr(11,2)), min=decimal(line.substr(14,2)), sec=decimal(line.substr(17,2));
    year_month_day date{year{y}, month{static_cast<unsigned>(m)}, day{static_cast<unsigned>(d)}};
    if (!date.ok() || h<0 || h>23 || min<0 || min>59 || sec<0 || sec>59 || decimal(line.substr(20,3))<0) return {};
    auto stamp = sys_days{date} + hours{h} + minutes{min} + seconds{sec};
    if (stamp > now || now-stamp > hours{24}) return {};
    auto field = line.substr(pos + marker.size());
    auto comma = field.find(", Port = ");
    if (comma == field.npos || comma > 45) return {};
    std::string host(field.substr(0,comma));
    if (host.find_first_not_of("0123456789abcdefABCDEF:.")!=host.npos) return {};
    auto port = field.substr(comma + 9);
    auto separator = port.find(" |");
    if (separator == port.npos) return {};
    int number = decimal(port.substr(0,separator));
    if (number < 1 || number > 65535) return {};
    try {
        auto target = parse_target(host.c_str());
        return GameRelay{target.text, std::string(line.substr(0,24))};
    } catch (const std::invalid_argument&) { return {}; }
}

std::optional<GameRelay> recent_roblox_relay(const std::filesystem::path& logs, std::chrono::sys_seconds now) {
    namespace fs = std::filesystem;
    std::vector<std::pair<fs::file_time_type,fs::path>> candidates;
    std::error_code ec;
    for (fs::directory_iterator it(logs,ec), end; !ec && it!=end; it.increment(ec)) {
        const auto& path=it->path();
        if (path.extension()!=L".log" || path.filename().wstring().find(L"_Player_")==std::wstring::npos) continue;
        DWORD attr=GetFileAttributesW(path.c_str());
        if (attr==INVALID_FILE_ATTRIBUTES || (attr & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))) continue;
        auto modified=it->last_write_time(ec);
        if (ec) {ec.clear();continue;}
        if (modified>=std::chrono::clock_cast<fs::file_time_type::clock>(now-std::chrono::hours{24}))
            candidates.emplace_back(modified,path);
    }
    std::sort(candidates.rbegin(),candidates.rend());
    std::optional<GameRelay> latest;
    for (size_t i=0; i<std::min<size_t>(8,candidates.size()); ++i) {
        std::ifstream file(candidates[i].second,std::ios::binary | std::ios::ate);
        if (!file) continue;
        auto size=static_cast<std::streamoff>(file.tellg());
        if (size<=0) continue;
        auto count=std::min<std::streamoff>(size,256*1024);
        file.seekg(size-count);
        std::string tail(static_cast<size_t>(count),'\0');
        file.read(tail.data(),count);
        tail.resize(static_cast<size_t>(file.gcount()));
        std::istringstream lines(std::move(tail));
        std::string line;
        if (size>count) std::getline(lines,line);
        while (std::getline(lines,line)) {
            auto relay=roblox_relay_line(line,now);
            if (relay && public_game_target(parse_target(relay->host.c_str())) && (!latest || relay->utc>latest->utc)) latest=std::move(relay);
        }
    }
    return latest;
}

std::optional<std::string> league_match_address(std::string_view log) {
    constexpr std::string_view connecting="CONN| Connecting to address (";
    constexpr std::string_view connected="CONN| Game Info Received: Initial Connection";
    std::optional<std::string> candidate, confirmed;
    while (!log.empty()) {
        auto end=log.find('\n');
        auto line=log.substr(0,end);
        auto at=line.find(connecting);
        if (at!=line.npos) {
            candidate.reset();
            auto fields=line.substr(at+connecting.size());
            auto split=fields.find(") port (");
            if (split<46 && fields.substr(split+8).find(')')!=fields.npos) {
                auto port=fields.substr(split+8);
                auto number=decimal(port.substr(0,port.find(')')));
                if (number>0 && number<=65535 && fields.substr(0,split).find_first_not_of("0123456789abcdefABCDEF:.")==fields.npos) {
                    try {candidate=parse_target(std::string(fields.substr(0,split)).c_str()).text;}
                    catch (const std::invalid_argument&) {}
                }
            }
        } else if (candidate && line.find(connected)!=line.npos) confirmed=candidate;
        if (end==log.npos) break;
        log.remove_prefix(end+1);
    }
    return confirmed;
}

std::optional<GameRelay> recent_league_match(const std::filesystem::path& logs, std::chrono::sys_seconds now) {
    namespace fs=std::filesystem;
    using namespace std::chrono;
    std::error_code ec;
    std::optional<GameRelay> latest;
    for (fs::directory_iterator it(logs,ec), end; !ec && it!=end; it.increment(ec)) {
        const auto& dir=it->path();
        auto name=dir.filename().wstring();
        if (name.size()!=19 || name.find_first_not_of(L"0123456789-T")!=name.npos ||
            name[4]!='-' || name[7]!='-' || name[10]!='T' || name[13]!='-' || name[16]!='-') continue;
        std::string stamp;
        for(wchar_t ch:name) stamp.push_back(static_cast<char>(ch));
        std::replace(stamp.begin()+11,stamp.end(),'-',':');
        SYSTEMTIME local{}, utc{};
        local.wYear=static_cast<WORD>(decimal(stamp.substr(0,4)));
        local.wMonth=static_cast<WORD>(decimal(stamp.substr(5,2)));
        local.wDay=static_cast<WORD>(decimal(stamp.substr(8,2)));
        local.wHour=static_cast<WORD>(decimal(stamp.substr(11,2)));
        local.wMinute=static_cast<WORD>(decimal(stamp.substr(14,2)));
        local.wSecond=static_cast<WORD>(decimal(stamp.substr(17,2)));
        if (!TzSpecificLocalTimeToSystemTime(nullptr,&local,&utc)) continue;
        sys_seconds started=sys_days{year{utc.wYear}/month{utc.wMonth}/day{utc.wDay}} +
            hours{utc.wHour}+minutes{utc.wMinute}+seconds{utc.wSecond};
        if (started>now || now-started>hours{24}) continue;
        auto file=dir/(name+L"_r3dlog.txt");
        DWORD folder=GetFileAttributesW(dir.c_str()), attr=GetFileAttributesW(file.c_str());
        if (folder==INVALID_FILE_ATTRIBUTES || (folder & FILE_ATTRIBUTE_REPARSE_POINT) ||
            attr==INVALID_FILE_ATTRIBUTES || (attr & (FILE_ATTRIBUTE_REPARSE_POINT|FILE_ATTRIBUTE_DIRECTORY))) continue;
        std::ifstream stream(file,std::ios::binary);
        if (!stream) continue;
        std::string header(256*1024,'\0');
        stream.read(header.data(),static_cast<std::streamsize>(header.size()));
        header.resize(static_cast<size_t>(stream.gcount()));
        auto host=league_match_address(header);
        if (host && public_game_target(parse_target(host->c_str()))) {
            char iso[32]{};
            std::snprintf(iso,sizeof iso,"%04u-%02u-%02uT%02u:%02u:%02uZ",
                unsigned(utc.wYear),unsigned(utc.wMonth),unsigned(utc.wDay),
                unsigned(utc.wHour),unsigned(utc.wMinute),unsigned(utc.wSecond));
            if (!latest || latest->utc<iso) latest=GameRelay{*host,iso};
        }
    }
    return latest;
}
