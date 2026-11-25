#include "speed_chart.hpp"
#include <algorithm>
#include <cmath>
#include <iomanip>
#include <sstream>

using namespace std::chrono_literals;

void SpeedChart::reset(std::uint64_t bytes) {
    started_ = Clock::now();
    counters_ = {{started_, bytes}};
    points_.clear();
}

void SpeedChart::sample(std::uint64_t bytes) {
    const auto now = Clock::now();
    // Keep the sample immediately before the one-second boundary.
    while (counters_.size() > 1 && counters_[1].at <= now - 1s) counters_.pop_front();
    const auto& first = counters_.front();
    const double seconds = std::chrono::duration<double>(now - first.at).count();
    if (seconds <= 0) return;
    const double rate = (bytes - first.bytes) * 8.0 / (seconds * 1000000);
    counters_.push_back({now, bytes});
    points_.push_back({now, rate});
    while (points_.size() > 1 && points_[1].at <= now - 6s) points_.pop_front();
}

std::wstring SpeedChart::readout() const {
    if (points_.empty()) return L"Oczekiwanie na dane";
    std::wostringstream text;
    text << std::fixed << std::setprecision(1) << points_.back().mbps;
    auto number = text.str();
    std::replace(number.begin(), number.end(), L'.', L',');
    return number + L" Mb/s";
}

void SpeedChart::paint(HDC dc, RECT bounds, HFONT normal, HFONT heading, bool upload) const {
    const int width = bounds.right - bounds.left, height = bounds.bottom - bounds.top;
    if (width < 200 || height < 60) return;
    // Double buffering keeps the line and its grid in the same animation frame.
    HDC frame = CreateCompatibleDC(dc);
    HBITMAP bitmap = CreateCompatibleBitmap(dc, width, height);
    if (!frame || !bitmap) {
        if (frame) DeleteDC(frame);
        if (bitmap) DeleteObject(bitmap);
        return;
    }
    HGDIOBJ previous = SelectObject(frame, bitmap);
    RECT area{0,0,width,height};
    FillRect(frame,&area,GetSysColorBrush(COLOR_WINDOW));
    SetBkMode(frame,TRANSPARENT);
    SetTextColor(frame,GetSysColor(COLOR_WINDOWTEXT));
    HGDIOBJ old_font = SelectObject(frame,normal);
    const auto label = upload ? L"Wysyłanie na żywo" : L"Pobieranie na żywo";
    RECT caption{12,12,185,42};
    DrawTextW(frame,label,-1,&caption,DT_LEFT|DT_SINGLELINE|DT_NOPREFIX);
    SelectObject(frame,heading);
    RECT value{12,45,189,92};
    auto text = readout();
    if (points_.empty()) SelectObject(frame,normal);
    DrawTextW(frame,text.c_str(),-1,&value,DT_LEFT|DT_SINGLELINE|DT_NOPREFIX);
    SelectObject(frame,normal);
    int left=194, right=width-12, top=30, bottom=height-15;
    double ceiling=10;
    for (const auto& p : points_) ceiling=std::max(ceiling,p.mbps);
    const double magnitude=std::pow(10,std::floor(std::log10(ceiling)));
    ceiling=std::ceil(ceiling/magnitude)*magnitude;
    auto scale=std::to_wstring(static_cast<unsigned long long>(ceiling))+L" Mb/s";
    RECT axis{left,2,right,25};
    DrawTextW(frame,scale.c_str(),-1,&axis,DT_RIGHT|DT_SINGLELINE|DT_NOPREFIX);
    const auto old_pen=SelectObject(frame,GetStockObject(DC_PEN));
    SetDCPenColor(frame,GetSysColor(COLOR_3DSHADOW));
    for (int y : {top,(top+bottom)/2,bottom}) {
        MoveToEx(frame,left,y,nullptr);
        LineTo(frame,right,y);
    }
    if (!points_.empty()) {
        auto from=std::max(started_,points_.back().at-6s);
        const COLORREF color = upload ? RGB(163,72,22) : RGB(0,109,99);
        HPEN stroke=CreatePen(PS_SOLID,3,color);
        if (stroke) {
            SelectObject(frame,stroke);
            bool first=true;
            for (const auto& p:points_) {
                const double elapsed=std::chrono::duration<double>(p.at-from).count();
                int x=left+static_cast<int>((right-left-1)*std::clamp(elapsed/6.0,0.0,1.0));
                int y=bottom-static_cast<int>((bottom-top)*p.mbps/ceiling);
                if (first) { MoveToEx(frame,x,y,nullptr); first=false; }
                LineTo(frame,x,y);
            }
            SelectObject(frame,old_pen);
            DeleteObject(stroke);
        }
    }
    SelectObject(frame,old_pen);
    SelectObject(frame,old_font);
    BitBlt(dc,bounds.left,bounds.top,width,height,frame,0,0,SRCCOPY);
    SelectObject(frame,previous);
    DeleteObject(bitmap);
    DeleteDC(frame);
}
