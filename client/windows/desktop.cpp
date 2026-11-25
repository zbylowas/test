#include "throughput.hpp"
#include "speed_chart.hpp"
#include "inventory_report.hpp"
#include "queue.hpp"
#include <wincred.h>
#include <wincrypt.h>
#include <algorithm>
#include <array>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <optional>
#include <sstream>
#include <thread>

namespace {
constexpr UINT done_message = WM_APP + 1, phase_message = WM_APP + 2;
constexpr UINT_PTR chart_timer = 1;
constexpr int chart_id = 104;
constexpr int start_id = 101, copy_id = 102, stop_id = 103;
constexpr wchar_t title[] = L"VIP-NET · Diagnostyka internetu";
HWND heading, intro, start_button, copy_button, stop_button, status_text, report_box;
HFONT normal_font, heading_font;
HWND chart_box;
LiveTraffic live_traffic;
SpeedChart chart;
int active_direction = 0;
std::jthread job;
std::atomic_bool cancelled{};
bool busy = false, closing = false;
std::wstring code, result_text;
const std::array<std::string,5> phases{"baseline","download","upload","recovery","sync"};
const std::array<const wchar_t*,5> labels{L"Pomiar w spoczynku",L"Pobieranie danych",L"Wysyłanie danych",
                                          L"Pomiar po obciążeniu",L"Synchronizacja raportu"};

std::wstring wide(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8,0,s.data(),static_cast<int>(s.size()),nullptr,0);
    std::wstring value(n,L' ');
    MultiByteToWideChar(CP_UTF8,0,s.data(),static_cast<int>(s.size()),value.data(),n);
    return value;
}

std::wstring origin() {
    auto configured = environment(L"VIPNET_DESKTOP_ORIGIN");
    return configured.empty() ? L"https://diagnostics.example.org" : configured;
}

std::wstring hash_name(const std::wstring& value) {
    BYTE digest[32]{}; DWORD length=sizeof digest;
    if (!CryptHashCertificate2(L"SHA256",0,nullptr,reinterpret_cast<const BYTE*>(value.data()),
                               static_cast<DWORD>(value.size()*sizeof(wchar_t)),digest,&length))
        throw std::runtime_error("windows_hash_failed");
    std::wostringstream stream;
    for (auto b : digest) stream << std::hex << std::setfill(L'0') << std::setw(2) << unsigned(b);
    return stream.str();
}

std::wstring credential(const std::wstring& host, bool create) {
    auto name = L"VIP-NET/Diagnostics/" + host;
    PCREDENTIALW record{};
    if (CredReadW(name.c_str(),CRED_TYPE_GENERIC,0,&record)) {
        std::wstring value(reinterpret_cast<wchar_t*>(record->CredentialBlob),record->CredentialBlobSize/sizeof(wchar_t));
        CredFree(record);
        return value;
    }
    if (GetLastError()!=ERROR_NOT_FOUND) throw std::runtime_error("windows_credential_read_failed");
    if (!create) return {};
    auto value=register_desktop_client(host);
    CREDENTIALW entry{};
    entry.Type=CRED_TYPE_GENERIC; entry.TargetName=name.data(); entry.Persist=CRED_PERSIST_LOCAL_MACHINE;
    entry.CredentialBlob=reinterpret_cast<LPBYTE>(value.data());
    entry.CredentialBlobSize=static_cast<DWORD>(value.size()*sizeof(wchar_t));
    if (!CredWriteW(&entry,0)) throw std::runtime_error("windows_credential_write_failed");
    return value;
}

std::filesystem::path profile(const std::wstring& host,const std::wstring& token) {
    auto base=environment(L"LOCALAPPDATA");
    if (base.empty()) throw std::runtime_error("local_app_data_unavailable");
    return std::filesystem::path(base)/L"VIP-NET"/L"Diagnostyka"/hash_name(host+L"\n"+token);
}

std::optional<double> median(const Json& rows) {
    std::vector<double> values;
    for (const auto& row:rows)
        if (row.at("error").is_null() && row.at("ms").is_number()) values.push_back(row.at("ms").get<double>());
    if (values.size()<5 || values.size()*5<rows.size()*4) return {};
    std::sort(values.begin(),values.end());
    return (values[(values.size()-1)/2]+values[values.size()/2])/2;
}

std::wstring render(const Json& data) {
    const auto& doc=data.at("throughput");
    std::wostringstream out;
    out << std::fixed << std::setprecision(2);
    out << (doc.at("error").is_null()?L"Raport z pomiaru":L"Raport częściowy") << L"\r\n\r\n";
    auto base=median(doc["phases"]["baseline"]), recovery=median(doc["phases"]["recovery"]);
    for (std::string dir:{"download","upload"}) {
        const auto& transfer=doc["transfers"][dir];
        out << (dir=="download"?L"Pobieranie":L"Wysyłanie") << L"   ";
        if (transfer["status"]!="ok" || !transfer["duration_ms"].is_number() ||
            transfer["duration_ms"].get<double>()<=0 || transfer["client_bytes"]!=transfer["node_bytes"]) {
            out << L"brak pełnego wyniku";
            if (transfer["reason"].is_string()) out << L" (" << wide(transfer["reason"].get<std::string>()) << L")";
        } else {
            out << transfer["client_bytes"].get<double>()*0.008/transfer["duration_ms"].get<double>() << L" Mb/s";
            auto load=median(doc["phases"][dir]);
            if (!base || !load) out << L"   ·   za mało próbek do oceny opóźnienia";
            else {
                double delta=*load-*base;
                out << L"   ·   zmiana opóźnienia " << std::showpos << delta << std::noshowpos << L" ms";
                if (delta<20) out << L"   ·   bez istotnego wzrostu";
                else if (recovery && std::abs(*recovery-*base)<10) out << L"   ·   możliwy bufferbloat";
                else out << L"   ·   wzrost pod obciążeniem, wynik niejednoznaczny";
            }
        }
        out << L"\r\n";
    }
    if (doc["profile"].is_object()) {
        const auto& profile = doc["profile"];
        out << L"Limit węzła   " << profile.at("rate_bps").get<double>() / 1000000 << L" Mb/s";
        if (profile.contains("streams")) out << L"   ·   strumienie: " << profile["streams"].get<int>()
            << L"   ·   okno: " << profile["window_ms"].get<int>()/1000.0 << L" s";
        out << L"\r\n";
    }
    out << L"\r\n" << wide(inventory_report(data.value("inventory",Json{}),doc));
    out << L"\r\nJakość połączenia · opóźnienie HTTPS i poprawne odpowiedzi\r\n";
    for (size_t i=0;i<4;++i) {
        auto val=median(doc["phases"][phases[i]]);
        out << labels[i] << L"   ";
        if(val) out << *val << L" ms"; else out << L"za mało poprawnych próbek";
        const auto& probes = doc["phases"][phases[i]];
        const auto good = std::count_if(probes.begin(),probes.end(),[](const Json& probe) {
            return probe.at("error").is_null() && probe.at("ms").is_number();
        });
        out << L"   ·   odpowiedzi " << good << L" / " << probes.size() << L"\r\n";
    }
    out << L"\r\nSesja   " << wide(doc.at("session_id")) << L"\r\nPoczątek UTC   " << wide(doc.at("started_at"))
        << L"\r\nSystem   " << wide(doc.at("windows_version")) << L"   ·   VIP-NET " << wide(data.value("version",std::string("0.5.0")));
    out << L"\r\nIP przy rezerwacji   " << (data.contains("observed_ip") && data["observed_ip"].is_string()
        ? wide(data["observed_ip"]) : L"brak rezerwacji lub starszy raport");
    out << L"\r\nIdentyfikator komputera   " << (data.contains("device") && data["device"]["id"].is_string()
        ? wide(data["device"]["id"]) : L"niedostępny");
    if (data.contains("device") && data["device"]["reason"].is_string())
        out << L" (" << wide(data["device"]["reason"]) << L")";
    if (!doc["error"].is_null()) out << L"\r\nPrzyczyna   " << wide(doc["error"]);
    out << (data.at("synchronized")==true?L"\r\nRaport dostępny w panelu klienta.":L"\r\nRaport zapisany lokalnie. Wysyłka oczekuje na synchronizację.");
    out << L"\r\n\r\nTrasa MTR";
    if (!data.contains("mtr_samples") || data["mtr_samples"].empty()) out << L"   ·   brak zapisanych próbek w raporcie lokalnym";
    else {
        for (size_t i=0; i<4; ++i) {
            out << L"\r\n\r\n" << labels[i] << L"\r\nPróba / skok     Router     RTT     Status\r\n";
            for (const auto& s : data["mtr_samples"]) {
                if (s["phase"] != phases[i]) continue;
                out << s["attempt"].get<int>() << L" / " << s["ttl"].get<int>() << L"     "
                    << (s["responder"].is_string()?wide(s["responder"]):L"—") << L"     ";
                if (s["rtt_ms"].is_number()) out << s["rtt_ms"].get<double>() << L" ms";
                else out << L"—";
                out << L"     " << wide(s["status"]) << L"\r\n";
            }
        }
    }
    return out.str();
}

void write_report(const std::filesystem::path& dir,const Json& report) {
    auto tmp=dir/L"last-report.tmp", dest=dir/L"last-report.json";
    std::ofstream file(tmp,std::ios::binary|std::ios::trunc);
    file.exceptions(std::ios::badbit|std::ios::failbit);
    file << report.dump(); file.close();
    if (!MoveFileExW(tmp.c_str(),dest.c_str(),MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH))
        throw std::runtime_error("local_report_write_failed");
}

void layout_report(HWND window) {
    RECT rect{};
    GetClientRect(window,&rect);
    const int width = std::max(1L,rect.right-48);
    const int top = active_direction ? 428 : 212;
    MoveWindow(chart_box,24,210,width,204,TRUE);
    ShowWindow(chart_box,active_direction ? SW_SHOWNA : SW_HIDE);
    MoveWindow(report_box,24,top,width,std::max(34L,rect.bottom-top-24),TRUE);
}

void end_chart(HWND window) {
    KillTimer(window,chart_timer);
    active_direction = 0;
    layout_report(window);
}

void run(HWND window) {
    live_traffic.received = 0;
    live_traffic.sent = 0;
    live_traffic.profile_bps = 0;
    busy=true; cancelled=false;
    EnableWindow(start_button,FALSE); EnableWindow(copy_button,FALSE); EnableWindow(stop_button,TRUE);
    SetWindowTextW(status_text,L"Łączenie z serwerem…");
    SetWindowTextW(report_box,L"Trwa przygotowanie pomiaru.");
    job=std::jthread([window] {
        try {
            auto host=origin();
            code=credential(host,true);
            auto dir=profile(host,code);
            SetEnvironmentVariableW(L"VIPNET_API_ORIGIN",host.c_str());
            SetEnvironmentVariableW(L"VIPNET_NODE_ORIGIN",host.c_str());
            SetEnvironmentVariableW(L"VIPNET_TOKEN",code.c_str());
            SetEnvironmentVariableW(L"VIPNET_QUEUE_DIR",dir.c_str());
            SetEnvironmentVariableW(L"VIPNET_PORTAL_RESERVATION",L"1");
            auto report=run_desktop_test(cancelled,[window](const std::string& phase){
                auto it=std::find(phases.begin(),phases.end(),phase);
                if(it!=phases.end()) PostMessageW(window,phase_message,it-phases.begin(),0);
            },live_traffic);
            result_text=render(report);
            write_report(dir,report);
        } catch(const std::exception& e) {
            result_text=L"Nie udało się zakończyć testu.\r\n\r\nSerwer   "+origin()+
                L"\r\nPrzyczyna   "+wide(e.what())+L"\r\n\r\nSprawdź połączenie i ponów test.";
        }
        PostMessageW(window,done_message,0,0);
    });
}

bool copy_secret(HWND window) {
    if(code.empty() || !OpenClipboard(window)) return false;
    struct Close { ~Close(){ CloseClipboard(); } } close;
    auto bytes=(code.size()+1)*sizeof(wchar_t);
    HANDLE memory=GlobalAlloc(GMEM_MOVEABLE,bytes);
    if(!memory) return false;
    auto buffer=GlobalLock(memory);
    if(!buffer){ GlobalFree(memory); return false; }
    memcpy(buffer,code.c_str(),bytes); GlobalUnlock(memory);
    if(!EmptyClipboard() || !SetClipboardData(CF_UNICODETEXT,memory)){ GlobalFree(memory); return false; }
    return true;
}

HWND control(HWND parent,const wchar_t* type,const wchar_t* text,DWORD style,int id,HFONT font) {
    auto w=CreateWindowExW(0,type,text,WS_CHILD|WS_VISIBLE|style,0,0,1,1,parent,
                           reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),GetModuleHandleW(nullptr),nullptr);
    SendMessageW(w,WM_SETFONT,reinterpret_cast<WPARAM>(font),TRUE);
    return w;
}

LRESULT CALLBACK dispatch(HWND w,UINT m,WPARAM a,LPARAM b) {
    switch(m) {
    case WM_CREATE: {
        normal_font=CreateFontW(-17,0,0,0,FW_NORMAL,0,0,0,DEFAULT_CHARSET,0,0,CLEARTYPE_QUALITY,0,L"Segoe UI");
        heading_font=CreateFontW(-30,0,0,0,FW_SEMIBOLD,0,0,0,DEFAULT_CHARSET,0,0,CLEARTYPE_QUALITY,0,L"Segoe UI");
        heading=control(w,L"STATIC",L"Diagnostyka internetu",0,0,heading_font);
        intro=control(w,L"STATIC",L"Sprawdź prędkość, opóźnienie, Wi-Fi i sieć lokalną. Raport z danymi komputera i trasą MTR trafi do Twojej historii w VIP-NET.",0,0,normal_font);
        start_button=control(w,L"BUTTON",L"Wykonaj test",WS_TABSTOP|BS_DEFPUSHBUTTON,start_id,normal_font);
        stop_button=control(w,L"BUTTON",L"Zatrzymaj",WS_TABSTOP,stop_id,normal_font);
        copy_button=control(w,L"BUTTON",L"Kopiuj kod do panelu",WS_TABSTOP,copy_id,normal_font);
        status_text=control(w,L"STATIC",L"Gotowy do pomiaru",0,0,normal_font);
        chart_box=control(w,L"STATIC",L"Prędkościomierz i wykres prędkości",SS_OWNERDRAW,chart_id,normal_font);
        ShowWindow(chart_box,SW_HIDE);
        report_box=control(w,L"EDIT",L"Wynik pojawi się tutaj po wykonaniu testu.",WS_BORDER|WS_TABSTOP|ES_MULTILINE|ES_READONLY|WS_VSCROLL,0,normal_font);
        try {
            auto host=origin(); code=credential(host,false);
            if(!code.empty()) {
                std::ifstream file(profile(host,code)/L"last-report.json",std::ios::binary);
                if(file) { auto report=Json::parse(file); SetWindowTextW(report_box,render(report).c_str()); }
            }
        } catch(const std::exception&) { SetWindowTextW(status_text,L"Poprzedni raport jest niedostępny."); }
        EnableWindow(stop_button,FALSE); EnableWindow(copy_button,!code.empty());
        return 0;
    }
    case WM_GETMINMAXINFO: {
        auto lim=reinterpret_cast<MINMAXINFO*>(b); lim->ptMinTrackSize={560,470}; return 0;
    }
    case WM_SIZE: {
        int width=LOWORD(b)-48;
        MoveWindow(heading,24,18,width,42,TRUE); MoveWindow(intro,24,67,width,50,TRUE);
        MoveWindow(start_button,24,121,145,40,TRUE); MoveWindow(stop_button,177,121,104,40,TRUE);
        MoveWindow(copy_button,289,121,194,40,TRUE); MoveWindow(status_text,24,178,width,27,TRUE);
        layout_report(w); return 0;
    }
    case WM_COMMAND:
        if(LOWORD(a)==start_id && !busy) run(w);
        if(LOWORD(a)==stop_id && busy) {cancelled=true; end_chart(w); SetWindowTextW(status_text,L"Zatrzymywanie pomiaru…");}
        if(LOWORD(a)==copy_id && !busy)
            SetWindowTextW(status_text,copy_secret(w)?L"Skopiowano prywatny kod logowania do panelu klienta.":L"Schowek jest niedostępny.");
        return 0;
    case WM_DRAWITEM:
        if(a==chart_id) {
            const auto& draw=*reinterpret_cast<const DRAWITEMSTRUCT*>(b);
            chart.paint(draw.hDC,draw.rcItem,normal_font,heading_font,active_direction==2);
            return TRUE;
        }
        break;
    case WM_TIMER:
        if(a==chart_timer && active_direction && !cancelled) {
            const auto bytes = active_direction==1 ? live_traffic.received.load() : live_traffic.sent.load();
            chart.sample(bytes);
            auto text=std::wstring(labels[active_direction])+L"   ·   "+chart.readout();
            SetWindowTextW(status_text,text.c_str());
            InvalidateRect(chart_box,nullptr,FALSE);
        }
        return 0;
    case phase_message:
        if(busy && !cancelled && a<labels.size()) {
            end_chart(w);
            SetWindowTextW(status_text,labels[a]);
            if(a==1 || a==2) {
                active_direction=static_cast<int>(a);
                chart.reset(a==1 ? live_traffic.received.load() : live_traffic.sent.load(),
                            live_traffic.profile_bps.load()/1000000.0);
                layout_report(w);
                SetTimer(w,chart_timer,50,nullptr);
            }
        }
        return 0;
    case done_message:
        job.join(); busy=false; end_chart(w);
        if(closing){DestroyWindow(w);return 0;}
        EnableWindow(start_button,TRUE); EnableWindow(stop_button,FALSE); EnableWindow(copy_button,!code.empty());
        SetWindowTextW(report_box,result_text.c_str()); SetWindowTextW(status_text,L"Test zakończony"); return 0;
    case WM_CLOSE:
        if(busy){ closing=true; cancelled=true; end_chart(w); SetWindowTextW(status_text,L"Zapis wyniku przed zamknięciem…"); }
        else DestroyWindow(w);
        return 0;
    case WM_DESTROY:
        DeleteObject(normal_font); DeleteObject(heading_font); PostQuitMessage(0); return 0;
    }
    return DefWindowProcW(w,m,a,b);
}
}

int WINAPI wWinMain(HINSTANCE instance,HINSTANCE,PWSTR,int show) {
    SetProcessDPIAware();
    WNDCLASSW cls{}; cls.hInstance=instance; cls.lpszClassName=L"VipNetDiagnosticsWindow";
    cls.lpfnWndProc=dispatch; cls.hCursor=LoadCursorW(nullptr,IDC_ARROW);
    cls.hbrBackground=reinterpret_cast<HBRUSH>(COLOR_BTNFACE+1); cls.hIcon=LoadIconW(nullptr,IDI_APPLICATION);
    if(!RegisterClassW(&cls)) return 1;
    auto w=CreateWindowW(cls.lpszClassName,title,WS_OVERLAPPEDWINDOW,CW_USEDEFAULT,CW_USEDEFAULT,800,650,nullptr,nullptr,instance,nullptr);
    if(!w) return 1;
    ShowWindow(w,show);
    MSG msg{};
    while(GetMessageW(&msg,nullptr,0,0)>0) {
        if (!IsDialogMessageW(w,&msg)){TranslateMessage(&msg); DispatchMessageW(&msg);}
    }
    return static_cast<int>(msg.wParam);
}
