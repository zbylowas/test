#include "speed_chart.hpp"
#include <algorithm>
#include <cmath>
#include <iomanip>
#include <numbers>
#include <sstream>

using namespace std::chrono_literals;

void SpeedChart::reset(std::uint64_t bytes, double scale_mbps) {
    started_ = Clock::now();
    scale_mbps_ = scale_mbps;
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

int SpeedChart::icon_step() const {
    if (points_.empty() || scale_mbps_<=0) return -1;
    return static_cast<int>(std::lround(20*std::clamp(points_.back().mbps/scale_mbps_,0.0,1.0)));
}

std::wstring SpeedChart::readout() const {
    if (points_.empty()) return L"Oczekiwanie na dane";
    std::wostringstream text;
    text << std::fixed << std::setprecision(1) << points_.back().mbps;
    auto number = text.str();
    std::replace(number.begin(), number.end(), L'.', L',');
    return number + L" Mb/s";
}

namespace {
POINT dial_point(int cx, int cy, double radius, double fraction) {
    const double angle = (1 - fraction) * std::numbers::pi;
    return {cx + static_cast<LONG>(std::lround(radius * std::cos(angle))),
            cy - static_cast<LONG>(std::lround(radius * std::sin(angle)))};
}
}

void paint_speed_needle(HDC dc, POINT center, int radius, int stroke, std::optional<double> progress,
                        bool upload, COLORREF track) {
    if (radius<=3*stroke) return;
    const auto saved = SaveDC(dc);
    const auto [cx,cy]=center;
    const double fraction=std::clamp(progress.value_or(0),0.0,1.0);
    const COLORREF accent = upload ? RGB(163,72,22) : RGB(0,109,99);
    SelectObject(dc,GetStockObject(DC_BRUSH));
    SelectObject(dc,GetStockObject(NULL_PEN));
    for (int i=0; i<120; ++i) {
        const double from=i/120.0, to=(i+1)/120.0;
        POINT segment[]={dial_point(cx,cy,radius,from),dial_point(cx,cy,radius,to),
                         dial_point(cx,cy,radius-stroke,to),dial_point(cx,cy,radius-stroke,from)};
        SetDCBrushColor(dc,to<=fraction ? accent : track);
        Polygon(dc,segment,4);
    }
    SelectObject(dc,GetStockObject(DC_PEN));
    SetDCPenColor(dc,GetSysColor(COLOR_GRAYTEXT));
    for (int i=0; i<=20; ++i) {
        const double position=i/20.0;
        const auto a=dial_point(cx,cy,radius-stroke*1.35,position);
        const auto b=dial_point(cx,cy,radius-stroke*(i%5==0 ? 2.6 : 2.0),position);
        MoveToEx(dc,a.x,a.y,nullptr); LineTo(dc,b.x,b.y);
    }
    if (progress) {
        const auto tip=dial_point(cx,cy,radius-stroke*2.8,fraction);
        const double angle=(1-fraction)*std::numbers::pi;
        const LONG dx=static_cast<LONG>(std::lround(stroke*.5*std::sin(angle)));
        const LONG dy=static_cast<LONG>(std::lround(stroke*.5*std::cos(angle)));
        POINT needle[]={{cx-dx,cy-dy},tip,{cx+dx,cy+dy}};
        const COLORREF ink=upload ? RGB(128,51,18) : RGB(0,72,86);
        SetDCBrushColor(dc,ink); SetDCPenColor(dc,ink);
        Polygon(dc,needle,3);
        const int hub=std::max(2,stroke*3/4);
        Ellipse(dc,cx-hub,cy-hub,cx+hub+1,cy+hub+1);
    }
    if (saved) RestoreDC(dc,saved);
}

namespace {
void dial(HDC dc, int width, int height, HFONT normal, HFONT heading, bool upload,
          double scale, double speed, const std::wstring& text) {
    const int cx = width / 2, cy = height - 60;
    const int radius = std::min(cx - 28, cy - 38);
    if (radius < 35) return;
    const auto saved = SaveDC(dc);
    SelectObject(dc,normal);
    const auto caption = upload ? L"Wysyłanie na żywo" : L"Pobieranie na żywo";
    RECT title{0,4,width,31};
    DrawTextW(dc,caption,-1,&title,DT_CENTER|DT_SINGLELINE|DT_NOPREFIX);
    const bool measured = speed >= 0 && scale > 0;
    paint_speed_needle(dc,{cx,cy},radius,8,measured?std::optional<double>{speed/scale}:std::nullopt,
                       upload,GetSysColor(COLOR_3DFACE));
    if (scale>0) {
        std::wostringstream end; end << std::setprecision(5) << scale;
        RECT lo{cx-radius-20,cy+3,cx-radius+20,cy+25},hi{cx+radius-29,cy+3,cx+radius+29,cy+25};
        DrawTextW(dc,L"0",-1,&lo,DT_CENTER|DT_SINGLELINE|DT_NOPREFIX);
        DrawTextW(dc,end.str().c_str(),-1,&hi,DT_CENTER|DT_SINGLELINE|DT_NOPREFIX);
    }
    SelectObject(dc,measured?heading:normal);
    RECT value{4,cy+16,width-4,height};
    DrawTextW(dc,text.c_str(),-1,&value,DT_CENTER|DT_SINGLELINE|DT_NOPREFIX);
    if (saved) RestoreDC(dc,saved);
}
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
    const int dial_width=std::min(292,width/2);
    dial(frame,dial_width,height,normal,heading,upload,scale_mbps_,
         points_.empty() ? -1.0 : points_.back().mbps,readout());
    int left=dial_width+12, right=width-12, top=40, bottom=height-25;
    double ceiling=10;
    for (const auto& p : points_) ceiling=std::max(ceiling,p.mbps);
    const double magnitude=std::pow(10,std::floor(std::log10(ceiling)));
    ceiling=std::ceil(ceiling/magnitude)*magnitude;
    auto scale=std::to_wstring(static_cast<unsigned long long>(ceiling))+L" Mb/s";
    RECT axis{left,2,right,25};
    DrawTextW(frame,L"Ostatnie 6 s",-1,&axis,DT_LEFT|DT_SINGLELINE|DT_NOPREFIX);
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
                if (&p == &points_.back()) {
                    const auto old_brush=SelectObject(frame,GetStockObject(DC_BRUSH));
                    SetDCBrushColor(frame,color);
                    Ellipse(frame,x-4,y-4,x+5,y+5);
                    SelectObject(frame,old_brush);
                }
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
