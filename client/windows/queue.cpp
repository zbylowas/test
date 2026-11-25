#include "inventory.hpp"
#include "queue.hpp"
#include <wincrypt.h>
#include <bcrypt.h>
#include <objbase.h>
#include <winsqlite/winsqlite3.h>
#include <algorithm>
#include <chrono>
#include <iostream>
#include <random>
#include <stdexcept>
#include <thread>
#include <vector>

std::wstring environment(const wchar_t* name) {
    DWORD size = GetEnvironmentVariableW(name, nullptr, 0);
    if (!size) return {};
    std::wstring value(size, L'\0');
    DWORD length = GetEnvironmentVariableW(name, value.data(), size);
    if (!length || length >= size) throw std::runtime_error("environment variable unavailable");
    value.resize(length);
    return value;
}

namespace {
void check(int rc) {
    if (rc != SQLITE_OK) throw std::runtime_error("SQLite error " + std::to_string(rc));
}

void execute(sqlite3* db, const char* sql) {
    check(sqlite3_exec(db, sql, nullptr, nullptr, nullptr));
}

class Statement {
public:
    Statement(sqlite3* db, const char* sql, const std::vector<std::string>& params = {}) {
        check(sqlite3_prepare_v2(db, sql, -1, &stmt_, nullptr));
        int n = 0;
        try {
            for (const auto& value : params)
                check(sqlite3_bind_text(stmt_, ++n, value.data(), static_cast<int>(value.size()), SQLITE_TRANSIENT));
        } catch (...) { sqlite3_finalize(stmt_); throw; }
    }
    ~Statement() { sqlite3_finalize(stmt_); }
    bool next() {
        int rc = sqlite3_step(stmt_);
        if (rc == SQLITE_ROW) return true;
        if (rc != SQLITE_DONE) check(rc);
        return false;
    }
    std::string field(int i) const {
        const auto* ptr = sqlite3_column_text(stmt_, i);
        return ptr ? reinterpret_cast<const char*>(ptr) : "";
    }
    int number(int i) const { return sqlite3_column_int(stmt_, i); }
private:
    sqlite3_stmt* stmt_{};
};

void update(sqlite3* db, const char* sql, const std::vector<std::string>& values = {}) {
    Statement query(db, sql, values);
    query.next();
}

class Transaction {
public:
    explicit Transaction(sqlite3* db) : db_(db) { execute(db_, "BEGIN IMMEDIATE"); }
    ~Transaction() { if (!committed_) sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr); }
    void commit() { execute(db_, "COMMIT"); committed_ = true; }
private:
    sqlite3* db_;
    bool committed_{};
};

std::filesystem::path directory() {
    auto path = environment(L"VIPNET_QUEUE_DIR");
    if (!path.empty()) return path;
    auto local = environment(L"LOCALAPPDATA");
    if (local.empty()) throw std::runtime_error("LOCALAPPDATA unavailable");
    return std::filesystem::path(local) / L"VIP-NET" / L"Internet Diagnostics";
}

struct FileLock {
    HANDLE value;
    explicit FileLock(const std::filesystem::path& path) {
        value = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE | DELETE, 0, nullptr, OPEN_ALWAYS,
                            FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, nullptr);
        if (value == INVALID_HANDLE_VALUE && GetLastError() != ERROR_SHARING_VIOLATION)
            throw std::runtime_error("queue lock unavailable");
    }
    ~FileLock() { if (value != INVALID_HANDLE_VALUE) CloseHandle(value); }
};

std::vector<std::string> ids(sqlite3* db, const char* sql) {
    Statement query(db, sql);
    std::vector<std::string> result;
    while (query.next()) result.push_back(query.field(0));
    return result;
}
}

Queue::Queue() : dir_(directory()) {
    std::filesystem::create_directories(dir_);
    auto path = dir_ / "queue.sqlite3";
    try {
        check(sqlite3_open16(path.c_str(), &db_));
        check(sqlite3_busy_timeout(db_, 10000));
        execute(db_, "PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL");
        Transaction tx(db_);
        {
            Statement version(db_, "PRAGMA user_version");
            if (!version.next() || version.number(0) > 1) throw std::runtime_error("unsupported queue version");
        }
        execute(db_, R"SQL(
          CREATE TABLE IF NOT EXISTS session(
            id TEXT PRIMARY KEY, opening TEXT NOT NULL, ending TEXT, next INTEGER NOT NULL DEFAULT -1,
            chunks INTEGER NOT NULL DEFAULT 0, failures INTEGER NOT NULL DEFAULT 0, due INTEGER NOT NULL DEFAULT 0,
            last_error INTEGER NOT NULL DEFAULT 0, blocked INTEGER NOT NULL DEFAULT 0, origin TEXT);
          CREATE TABLE IF NOT EXISTS sample(
            n INTEGER PRIMARY KEY, id TEXT NOT NULL REFERENCES session ON DELETE CASCADE, body TEXT NOT NULL);
          CREATE INDEX IF NOT EXISTS sample_session ON sample(id,n);
          CREATE TABLE IF NOT EXISTS chunk(
            id TEXT REFERENCES session ON DELETE CASCADE, n INTEGER, body TEXT NOT NULL, PRIMARY KEY(id,n));
          CREATE TABLE IF NOT EXISTS privacy_key(k INTEGER PRIMARY KEY CHECK(k=1), protected BLOB NOT NULL);
          CREATE TABLE IF NOT EXISTS gateway_seen(device TEXT, ip TEXT, mac TEXT NOT NULL, observed TEXT NOT NULL,
            PRIMARY KEY(device,ip));
          PRAGMA user_version=1;
        )SQL");
        tx.commit();
    } catch (...) { sqlite3_close(db_); throw; }
}

Queue::~Queue() {
    if (recording_ != INVALID_HANDLE_VALUE) CloseHandle(recording_);
    sqlite3_close(db_);
}

namespace {
std::string scoped_uuid(const std::string& scope, const unsigned char* value, size_t length) {
    std::string input = "VIP-NET/InternetDiagnostics/device/v1/" + scope + "/";
    input.append(reinterpret_cast<const char*>(value), length);
    BYTE digest[32]{};
    DWORD size = sizeof(digest);
    if (!CryptHashCertificate2(L"SHA256", 0, nullptr, reinterpret_cast<const BYTE*>(input.data()),
                               static_cast<DWORD>(input.size()), digest, &size) || size != sizeof(digest))
        throw std::runtime_error("device_hash_unavailable");
    digest[6] = (digest[6] & 15) | 0x80;
    digest[8] = (digest[8] & 63) | 0x80;
    constexpr char digits[] = "0123456789abcdef";
    std::string uuid;
    for (int i = 0; i < 16; ++i) {
        if (i == 4 || i == 6 || i == 8 || i == 10) uuid += '-';
        uuid += digits[digest[i] >> 4];
        uuid += digits[digest[i] & 15];
    }
    return uuid;
}

Json device_identity(Queue& queue) {
    wchar_t guid[64]{};
    DWORD length = sizeof(guid);
    GUID parsed{};
    const auto rc = RegGetValueW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", L"MachineGuid",
        RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY, nullptr, guid, &length);
    try {
        if (rc == ERROR_SUCCESS && wcsnlen_s(guid,64) == 36 &&
            SUCCEEDED(IIDFromString((L"{" + std::wstring(guid) + L"}").c_str(), &parsed)))
            return {{"method","windows_installation_v1"},{"reason",nullptr},
                    {"id",scoped_uuid("installation",reinterpret_cast<const BYTE*>(&parsed),sizeof(parsed))}};
        auto key = queue.privacy_key();
        return {{"method","local_profile_v1"},{"reason","machine_guid_unavailable"},
                {"id",scoped_uuid("profile",key.data(),key.size())}};
    } catch (const std::exception&) {
        return {{"method","unavailable"},{"reason","device_identity_unavailable"},{"id",nullptr}};
    }
}
}

std::vector<std::string> Queue::recorded_samples(const std::string& id) {
    Statement samples(db_, "SELECT body FROM sample WHERE id=? ORDER BY n", {id});
    std::vector<std::string> rows;
    while (samples.next()) rows.push_back(samples.field(0));
    return rows;
}

std::string Queue::begin(const std::string& id, const std::string& measurement) {
    FileLock lock(dir_ / (id + ".lock"));
    if (lock.value == INVALID_HANDLE_VALUE) throw std::runtime_error("recording already exists");
    const auto device = device_identity(*this).dump();
    auto body = "{\"schema_version\":1,\"device\":" + device + ",\"session_id\":\"" + id + "\",\"started_at\":\"" + utc_now()
        + "\",\"client_version\":\"0.7.4\",\"mode\":\"portable\""
        + (measurement.empty() ? std::string{} : ",\"measurement\":" + measurement) + "}";
    update(db_, "INSERT INTO session(id,opening) VALUES (?,?)", {id, body});
    recording_ = lock.value;
    lock.value = INVALID_HANDLE_VALUE;
    return device;
}

std::vector<unsigned char> Queue::privacy_key() {
    Transaction tx(db_);
    Statement read(db_, "SELECT protected FROM privacy_key WHERE k=1");
    Bytes key(32);
    if (read.next()) {
        std::string hex = read.field(0);
        if (hex.empty() || hex.size() % 2 || hex.size() > 8192)
            throw std::runtime_error("invalid protected identity");
        Bytes encoded;
        for (size_t i = 0; i < hex.size(); i += 2)
            encoded.push_back(static_cast<unsigned char>(std::stoul(hex.substr(i, 2), nullptr, 16)));
        DATA_BLOB in{static_cast<DWORD>(encoded.size()), encoded.data()}, decoded{};
        if (!CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &decoded))
            throw std::runtime_error("identity belongs to a different Windows account or is unavailable");
        const bool valid = decoded.cbData == key.size();
        if (valid)
            std::copy_n(decoded.pbData, key.size(), key.data());
        SecureZeroMemory(decoded.pbData, decoded.cbData);
        LocalFree(decoded.pbData);
        if (!valid)
            throw std::runtime_error("invalid identity key length");
    } else {
        if (!BCRYPT_SUCCESS(BCryptGenRandom(nullptr, key.data(), static_cast<ULONG>(key.size()),
                                            BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
            throw std::runtime_error("system randomness unavailable");
        DATA_BLOB in{static_cast<DWORD>(key.size()), key.data()}, encoded{};
        if (!CryptProtectData(&in, L"VIP-NET MAC HMAC", nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN,
                              &encoded))
            throw std::runtime_error("could not protect installation identity");
        std::string hex;
        constexpr char digits[] = "0123456789abcdef";
        for (DWORD i = 0; i < encoded.cbData; ++i) {
            hex += digits[encoded.pbData[i] >> 4];
            hex += digits[encoded.pbData[i] & 15];
        }
        LocalFree(encoded.pbData);
        update(db_, "INSERT INTO privacy_key(k,protected) VALUES(1,?)", {hex});
    }
    tx.commit();
    return key;
}

std::string Queue::save_inventory(const std::string& id) {
    auto key = privacy_key();
    auto doc = collect_inventory(key);
    SecureZeroMemory(key.data(), key.size());
    const std::string now = doc.at("captured_at");
    Transaction tx(db_);
    Json changes = Json::array();
    size_t current = 0, comparable = 0;
    bool incomplete = false;
    if (doc["interfaces"].contains("value") && doc["neighbors"].contains("value")) {
        incomplete = doc["interfaces"]["status"] != "ok" || doc["neighbors"]["status"] != "ok";
        for (const auto& nic : doc["interfaces"]["value"]) {
            const std::string device = nic.at("id");
            if (nic["gateways"]["status"] != "ok")
                incomplete = true;
            for (const auto& ip : nic["gateways"]["value"]) {
                auto& neighbors = doc["neighbors"]["value"];
                auto entry = std::find_if(neighbors.begin(), neighbors.end(), [&](const auto& row) {
                    return row["index"] == nic["index"] && row["ip"] == ip;
                });
                if (entry == neighbors.end()) {
                    incomplete = true;
                    continue;
                }
                ++current;
                std::string mac = entry->at("mac_id").at("value");
                Statement prev(db_, "SELECT mac,observed FROM gateway_seen WHERE device=? AND ip=?",
                               {device, ip});
                if (prev.next()) {
                    if (prev.field(1) >= now)
                        continue;
                    ++comparable;
                    if (prev.field(0) != mac)
                        changes.push_back({{"interface_id", device},
                                           {"ip", ip},
                                           {"previous_mac_id", prev.field(0)},
                                           {"current_mac_id", mac}});
                }
                update(db_, "INSERT OR REPLACE INTO gateway_seen(device,ip,mac,observed) VALUES(?,?,?,?)",
                       {device, ip, mac, now});
            }
        }
    } else
        incomplete = true;
    if (!current)
        doc["gateway_changes"] = unavailable("no_observed_gateway_mac");
    else if (!comparable)
        doc["gateway_changes"] = unavailable("no_previous_gateway_observation");
    else if (incomplete || comparable < current)
        doc["gateway_changes"] = {{"status", "partial"},
                                  {"reason", "gateway_observation_incomplete"},
                                  {"total", changes.size()},
                                  {"value", changes}};
    else
        doc["gateway_changes"] = available(changes);
    // Keep the opening below the API wire limit even on densely configured Windows hosts.
    while (doc.dump().size() > 220 * 1024) {
        Json* largest = nullptr;
        size_t size = 0;
        for (auto section :
             {"interfaces", "routes", "neighbors", "wifi", "duplicate_addresses", "gateway_changes"}) {
            auto& part = doc.at(section);
            if (part.contains("value") && !part.at("value").empty() && part.at("value").dump().size() > size) {
                largest = &part;
                size = part.at("value").dump().size();
            }
        }
        if (!largest)
            throw std::runtime_error("inventory exceeds wire budget");
        auto& part = *largest;
        if (!part.contains("total"))
            part["total"] = part["value"].size();
        part["status"] = "partial";
        part["reason"] = "wire_budget";
        part["value"].erase(part["value"].end() - 1);
    }
    Statement opening(db_, "SELECT opening FROM session WHERE id=? AND ending IS NULL", {id});
    if (!opening.next())
        throw std::runtime_error("missing recording session");
    Json body = Json::parse(opening.field(0));
    body["inventory"] = std::move(doc);
    auto serialized = body.dump();
    update(db_, "UPDATE session SET opening=? WHERE id=?", {serialized, id});
    tx.commit();
    return serialized;
}

void Queue::save_throughput(const std::string& id, const std::string& document) {
    Statement row(db_, "SELECT opening FROM session WHERE id=? AND ending IS NULL", {id});
    if (!row.next()) throw std::runtime_error("missing recording session");
    auto opening = Json::parse(row.field(0));
    opening["throughput"] = Json::parse(document);
    update(db_, "UPDATE session SET opening=? WHERE id=?", {opening.dump(), id});
}

void Queue::append(const std::string& id, const std::string& sample) {
    update(db_, "INSERT INTO sample(id,body) VALUES (?,?)", {id, sample});
}

void Queue::seal(const std::string& id, const std::string& state) {
    Transaction tx(db_);
    Statement samples(db_, "SELECT body FROM sample WHERE id=? ORDER BY n", {id});
    int count = 0, n = 0;
    std::string buffer;
    auto flush = [&] {
        if (!count) return;
        update(db_, "INSERT INTO chunk VALUES (?,?,?)",
               {id, std::to_string(n++), "{\"schema_version\":1,\"samples\":[" + buffer + "]}"});
        count = 0;
        buffer.clear();
    };
    while (samples.next()) {
        if (count) buffer += ",";
        buffer += samples.field(0);
        if (++count == 64) flush();
    }
    flush();
    auto body = "{\"schema_version\":1,\"state\":\"" + state + "\",\"ended_at\":\"" + utc_now()
        + "\",\"chunk_count\":" + std::to_string(n) + "}";
    update(db_, "UPDATE session SET ending=?,chunks=? WHERE id=? AND ending IS NULL", {body,std::to_string(n),id});
    update(db_, "DELETE FROM sample WHERE id=?", {id});
    tx.commit();
}

void Queue::recover() {
    for (const auto& id : ids(db_, "SELECT id FROM session WHERE ending IS NULL")) {
        GUID parsed{};
        auto guid = L"{" + std::wstring(id.begin(),id.end()) + L"}";
        if (id.size() != 36 || FAILED(IIDFromString(guid.c_str(), &parsed)))
            throw std::runtime_error("invalid session ID in queue");
        FileLock lock(dir_ / (id + ".lock"));
        if (lock.value != INVALID_HANDLE_VALUE) {
            bool orphan;
            {
                Statement query(db_, "SELECT 1 FROM session WHERE id=? AND ending IS NULL", {id});
                orphan = query.next();
            }
            if (orphan) seal(id, "partial");
        }
    }
}

bool Queue::deliver(const Sender& sender, const std::string& id) {
    for (;;) {
        int next, chunks, failures;
        std::string body, path = "/api/v1/sessions/" + id;
        {
            Statement row(db_, "SELECT next,chunks,failures,opening,ending FROM session WHERE id=?", {id});
            if (!row.next()) return true;
            next=row.number(0); chunks=row.number(1); failures=row.number(2);
            if (next < 0) body=row.field(3);
            else if (next == chunks) { path += "/completion"; body=row.field(4); }
            else {
                Statement part(db_, "SELECT body FROM chunk WHERE id=? AND n=?", {id,std::to_string(next)});
                if (!part.next()) throw std::runtime_error("missing local chunk");
                body=part.field(0);
                path += "/chunks/" + std::to_string(next);
            }
        }
        auto reply = sender.put(path, body, next >= 0 && next < chunks);
        bool accepted = next < 0 ? (reply.status == 201 || reply.status == 200)
                      : next == chunks ? (reply.status == 202 || reply.status == 200) : reply.status == 204;
        if (accepted && (next < 0 || next == chunks)) {
            // A generic HTTP 200 page is not an acknowledgement of this manifest.
            Statement ack(db_, "SELECT CASE WHEN json_valid(?1) THEN lower(json_extract(?1,'$.session_id'))=lower(?2)"
                               " AND (?3='open' OR json_extract(?1,'$.state')=json_extract(?4,'$.state')) ELSE 0 END",
                          {reply.body,id,next < 0 ? "open" : "finish",body});
            accepted = ack.next() && ack.number(0);
            if (!accepted) reply.status = -ERROR_INVALID_DATA;
        }
        if (!accepted) {
            bool permanent = reply.status == 409 || reply.status == 413 || reply.status == 422;
            unsigned base = 1u << std::min(failures, 9);
            unsigned delay = std::max(reply.retry_after, base + std::random_device{}() % (base + 1));
            update(db_, "UPDATE session SET failures=failures+1,last_error=?,blocked=?,due=strftime('%s','now')+? WHERE id=?",
                   {std::to_string(reply.status), permanent ? "1" : "0", std::to_string(delay),id});
            return false;
        }
        if (next == chunks) {
            update(db_, "DELETE FROM session WHERE id=?", {id});
            return true;
        }
        update(db_, "UPDATE session SET next=next+1,failures=0,due=0,last_error=0 WHERE id=?", {id});
    }
}

int Queue::sync(bool wait, bool retry_blocked) {
    FileLock uploader(dir_ / "upload.lock");
    if (uploader.value == INVALID_HANDLE_VALUE) return 3;
    recover();
    Sender sender;
    if (retry_blocked)
        update(db_, "UPDATE session SET blocked=0,due=0 WHERE blocked=1 AND origin=?", {sender.origin});
    for (;;) {
        auto pending = ids(db_, "SELECT id FROM session WHERE ending IS NOT NULL AND blocked=0 "
                                "AND due<=CAST(strftime('%s','now') AS INTEGER) ORDER BY rowid");
        for (const auto& id : pending) {
            update(db_, "UPDATE session SET origin=? WHERE id=? AND origin IS NULL", {sender.origin,id});
            bool matches;
            {
                Statement profile(db_, "SELECT 1 FROM session WHERE id=? AND origin=?", {id,sender.origin});
                matches = profile.next();
            }
            if (matches) deliver(sender,id);
        }
        Statement counts(db_, "SELECT count(*),coalesce(sum(CASE WHEN blocked=0 AND (origin=? OR origin IS NULL)"
                              " AND last_error NOT IN (401,403) THEN 1 ELSE 0 END),0) FROM session WHERE ending IS NOT NULL",
                         {sender.origin});
        counts.next();
        if (!counts.number(0)) return 0;
        if (!wait || !counts.number(1)) return 3;
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

void Queue::status() {
    Statement rows(db_, "SELECT id,ending IS NULL,next,chunks,blocked,last_error,due FROM session ORDER BY rowid");
    while (rows.next()) {
        std::cout << rows.field(0) << " recording=" << rows.number(1) << " next=" << rows.number(2)
                  << " chunks=" << rows.number(3) << " blocked=" << rows.number(4)
                  << " last_error=" << rows.number(5) << " retry_epoch=" << rows.field(6) << '\n';
    }
}
