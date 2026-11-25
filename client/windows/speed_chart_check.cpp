#include "speed_chart.hpp"
#include <iostream>
#include <stdexcept>
#include <vector>

namespace {
constexpr int width=620, height=204;
void require(bool condition) {
    if (!condition) throw std::runtime_error("chart regression");
}

// Render to an off-screen DIB. Only the plotted area contributes to the result.
std::vector<DWORD> plotted(SpeedChart& chart, bool upload, bool needle=false) {
    HDC dc=CreateCompatibleDC(nullptr);
    BITMAPINFO info{};
    info.bmiHeader.biSize=sizeof(BITMAPINFOHEADER);
    info.bmiHeader.biWidth=width;
    info.bmiHeader.biHeight=-height;
    info.bmiHeader.biPlanes=1;
    info.bmiHeader.biBitCount=32;
    void* pixels{};
    HBITMAP bitmap=CreateDIBSection(dc,&info,DIB_RGB_COLORS,&pixels,nullptr,0);
    require(dc && bitmap && pixels);
    auto old=SelectObject(dc,bitmap);
    auto font=static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));
    chart.paint(dc,{0,0,width,height},font,font,upload);
    GdiFlush();
    std::vector<DWORD> trace;
    const DWORD color=needle ? (upload ? 0x803312 : 0x004856) : (upload ? 0xa34816 : 0x006d63);
    for (int y=29; y<height-10; ++y)
        for (int x=needle?10:304; x<(needle?286:width-12); ++x)
            if ((static_cast<DWORD*>(pixels)[y*width+x] & 0xffffffu)==color)
                trace.push_back(y*width+x);
    SelectObject(dc,old);
    DeleteObject(bitmap);
    DeleteDC(dc);
    return trace;
}
}

int main() {
    try {
        for (bool upload : {false,true}) {
            SpeedChart chart;
            chart.reset(1000,100);
            require(plotted(chart,upload,true).empty());
            require(chart.readout()==L"Oczekiwanie na dane");
            Sleep(75);
            chart.sample(1000);
            require(chart.readout()==L"0,0 Mb/s");
            auto zero=plotted(chart,upload,true);
            require(!zero.empty());
            Sleep(75);
            chart.sample(501000);
            require(chart.readout()!=L"0,0 Mb/s");
            auto before=plotted(chart,upload);
            auto needle_before=plotted(chart,upload,true);
            require(!needle_before.empty() && needle_before!=zero);
            Sleep(100);
            chart.sample(1801000);
            auto after=plotted(chart,upload);
            require(!before.empty() && !after.empty() && before!=after);
            require(plotted(chart,upload,true)!=needle_before);
            chart.reset(1801000,1000);
            require(plotted(chart,upload).empty() && plotted(chart,upload,true).empty());
        }
        std::cout << "Download and upload dial, independent needle, plot, counters and reset passed\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
