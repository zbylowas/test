#pragma once
#include <filesystem>
#include <memory>
#include <string>
#include <vector>
#include <windows.h>

struct sqlite3;

struct Delivery {
    int status{};
    unsigned retry_after{};
    std::string body;
};

class Sender {
public:
    Sender();
    Delivery put(const std::string& path, const std::string& body, bool compress) const;
    std::string origin;
private:
    std::wstring host_, bearer_;
    unsigned short port_{};
};

std::string utc_now();
std::wstring environment(const wchar_t* name);

class Queue {
public:
    Queue();
    ~Queue();
    Queue(const Queue&) = delete;
    Queue& operator=(const Queue&) = delete;
    std::vector<std::string> recorded_samples(const std::string& id);
    std::string begin(const std::string& id, const std::string& measurement);
    std::vector<unsigned char> privacy_key();
    std::string save_inventory(const std::string& id);
    void save_throughput(const std::string& id, const std::string& document);
    void append(const std::string& id, const std::string& sample);
    void seal(const std::string& id, const std::string& state);
    int sync(bool wait, bool retry_blocked=false);
    void status();
private:
    sqlite3* db_{};
    std::filesystem::path dir_;
    HANDLE recording_{INVALID_HANDLE_VALUE};
    void recover();
    bool deliver(const Sender& sender, const std::string& id);
};
