#pragma once
#include <windows.h>
#include <chrono>
#include <cstdint>
#include <deque>
#include <string>

class SpeedChart {
public:
    void reset(std::uint64_t bytes);
    void sample(std::uint64_t bytes);
    std::wstring readout() const;
    void paint(HDC dc, RECT bounds, HFONT normal, HFONT heading, bool upload) const;
private:
    using Clock = std::chrono::steady_clock;
    struct Counter { Clock::time_point at; std::uint64_t bytes; };
    struct Point { Clock::time_point at; double mbps; };
    Clock::time_point started_{};
    std::deque<Counter> counters_;
    std::deque<Point> points_;
};
