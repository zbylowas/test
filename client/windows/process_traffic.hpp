#pragma once
#include "detail_pages.hpp"
#include <memory>

namespace traffic {
class Capture {
public:
    Capture();
    ~Capture();
    Capture(const Capture&)=delete;
    Capture& operator=(const Capture&)=delete;

    bool start(HWND owner);
    void use_adapter(const Json& local_ip);
    void finish();
    summary::DetailPage page(bool live, const std::wstring& phase);

private:
    struct State;
    std::unique_ptr<State> state_;
};

int run_helper(std::wstring_view arguments);
#ifdef VIPNET_TRAFFIC_TEST
int verify_loopback();
#endif
}
