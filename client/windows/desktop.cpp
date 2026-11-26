#include "throughput.hpp"
#include "summary_view.hpp"
#include "update.hpp"
#include "game_relay.hpp"
#include "live_diagnostics.hpp"
#include "process_traffic.hpp"
#include "desktop_brand.hpp"
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#include "inventory_report.hpp"
#include "reader_report.hpp"
#include "queue.hpp"
#include <wincred.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <commdlg.h>
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
using namespace summary;
constexpr UINT done_message=WM_APP+1,phase_message=WM_APP+2;
constexpr UINT_PTR chart_timer=1, process_timer=3;
View view;
LiveTraffic live_traffic;
std::unique_ptr<traffic::Capture> process_capture;
std::wstring process_phase;
int active_direction=0;
int window_icon_id = 0;
void set_window_icon(HWND window,int step) {
    const int id=step<0 ? 1 : 20+step;
    if (window_icon_id==id) return;
    for (int kind:{ICON_SMALL,ICON_BIG}) {
        const int size=GetSystemMetrics(kind==ICON_SMALL?SM_CXSMICON:SM_CXICON);
        auto icon=LoadImageW(GetModuleHandleW(nullptr),MAKEINTRESOURCEW(id),IMAGE_ICON,size,size,LR_SHARED);
        if (icon) SendMessageW(window,WM_SETICON,kind,reinterpret_cast<LPARAM>(icon));
    }
    window_icon_id=id;
}
std::jthread job;
std::atomic_bool cancelled{};
bool busy = false, closing = false;
std::wstring code, result_text, technical_text;
Json last_report,worker_report;
std::wstring worker_error;
bool loading=false,technical=false,report_open=false;
constexpr wchar_t placement_key[]=L"Software\\NetDiagnostics\\Portable";

const std::array<std::string,6> phases{"baseline","download","upload","recovery","sync","ping"};
const std::array<const wchar_t*,6> labels{L"Pomiar w spoczynku",L"Pobieranie danych",L"Wysyłanie danych",
                                          L"Pomiar po obciążeniu",L"Zapisywanie raportu",L"Sprawdzanie odpowiedzi routera i serwera"};

std::wstring wide(const std::string& s) {
    return summary::from_utf8(s);
}

std::wstring setting(const wchar_t* key,const wchar_t* fallback) {
    std::wstring path(32768,L'\0');
    auto n=GetModuleFileNameW(nullptr,path.data(),static_cast<DWORD>(path.size()));
    path.resize(n);
    auto ini=std::filesystem::path(path).parent_path()/L"NetDiagnostics.ini";
    wchar_t value[2048]{};
    GetPrivateProfileStringW(L"NetDiagnostics",key,fallback,value,2048,ini.c_str());
    return value;
}
std::wstring origin() {
    auto configured=environment(L"VIPNET_DESKTOP_ORIGIN");
    return configured.empty()?setting(L"Server",default_server):configured;
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

std::wstring render_technical(const Json& data) {
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

void write_atomic(const std::filesystem::path& dest,const std::string& bytes) {
    auto tmp=dest;tmp+=L"."+std::to_wstring(GetCurrentProcessId())+L".tmp";
    try {
        std::ofstream file(tmp,std::ios::binary|std::ios::trunc);
        file.exceptions(std::ios::badbit|std::ios::failbit);
        file<<bytes;file.close();
        if (!MoveFileExW(tmp.c_str(),dest.c_str(),MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH))
            throw std::runtime_error("local_report_write_failed");
    } catch (...) {
        DeleteFileW(tmp.c_str());throw;
    }
}
void write_report(const std::filesystem::path& dir,const Json& report) {
    const auto history=dir/L"reports", latest=dir/L"last-report.json";
    std::filesystem::create_directories(history);
    auto archive=[&](const Json& data,const std::string& bytes) {
        auto id=data.at("throughput").at("session_id").get<std::string>();
        if (id.size()!=36 || id.find_first_not_of("0123456789abcdefABCDEF-")!=id.npos)
            throw std::runtime_error("invalid_local_report_id");
        auto file=history/(id+".json");
        if (!std::filesystem::exists(file)) write_atomic(file,bytes);
    };
    if (std::ifstream previous(latest,std::ios::binary);previous) {
        std::string content((std::istreambuf_iterator<char>(previous)),{});
        auto old=Json::parse(content,nullptr,false);
        if (old.is_object() && old.contains("throughput") && old["throughput"].contains("session_id")) archive(old,content);
        else write_atomic(history/(L"unreadable-"+hash_name(wide(content))+L".json"),content);
    }
    auto content=report.dump();archive(report,content);write_atomic(latest,content);
}

void end_chart(HWND window) {
    KillTimer(window,chart_timer);
    set_window_icon(window,-1);
    active_direction=0;
}

void run(HWND window,bool measure_processes=false) {
    process_capture=measure_processes?std::make_unique<traffic::Capture>():nullptr;
    auto* capture=process_capture.get();
    live_traffic.on_measurement_adapter=capture?[capture](const Json& ip){capture->use_adapter(ip);}:std::function<void(const Json&)>{};
    live_traffic.clear();
    live_traffic.capacity=view.capacity();
    busy=true;cancelled=false;technical=false;report_open=false;
    worker_report=nullptr;worker_error.clear();result_text.clear();technical_text.clear();
    for(int i=0;i<12;++i)EnableWindow(GetDlgItem(window,nav_id+i),FALSE);
    if(capture){
        process_phase=L"Uruchamianie testu";
        view.workspace(2,capture->page(true,process_phase));
        SetDlgItemTextW(window,process_test_id,L"Zatrzymaj pomiar");
        SetTimer(window,process_timer,1000,nullptr);
    }else view.home();
    view.update(summary::read(nullptr));view.controls(true,false,false);
    view.phase(capture?L"Oczekiwanie na licznik ruchu Windows…":L"Łączenie z serwerem…");
    SetFocus(GetDlgItem(window,capture?process_test_id:stop_id));
    job=std::jthread([window,capture] {
        try {
            auto host=origin();
            if (host.empty()) throw std::runtime_error("central_server_not_configured");
            if(capture)capture->start(window);
            if(cancelled)throw std::runtime_error("cancelled");
            code=credential(host,true);
            auto dir=profile(host,code);
            SetEnvironmentVariableW(L"VIPNET_API_ORIGIN",host.c_str());
            SetEnvironmentVariableW(L"VIPNET_NODE_ORIGIN",host.c_str());
            SetEnvironmentVariableW(L"VIPNET_TOKEN",code.c_str());
            SetEnvironmentVariableW(L"VIPNET_QUEUE_DIR",dir.c_str());
            SetEnvironmentVariableW(L"VIPNET_PORTAL_RESERVATION",L"1");
            worker_report=run_desktop_test(cancelled,[window](const std::string& phase){
                auto it=std::find(phases.begin(),phases.end(),phase);
                if(it!=phases.end()) PostMessageW(window,phase_message,it-phases.begin(),0);
            },live_traffic);
            write_report(dir,worker_report);
        } catch(const std::exception& e) {worker_error=wide(e.what());}
        if(capture)capture->finish();
        PostMessageW(window,done_message,0,0);
    });
}
bool copy_text(HWND window, const std::wstring& value) {
    if(value.empty() || !OpenClipboard(window))return false;
    struct Close { ~Close(){ CloseClipboard(); } } close;
    const auto size=(value.size()+1)*sizeof(wchar_t);
    auto memory=GlobalAlloc(GMEM_MOVEABLE,size);
    if(!memory)return false;
    auto destination=GlobalLock(memory);
    if(!destination){GlobalFree(memory);return false;}
    memcpy(destination,value.c_str(),size);GlobalUnlock(memory);
    if(!EmptyClipboard() || !SetClipboardData(CF_UNICODETEXT,memory)){GlobalFree(memory);return false;}
    return true;
}
HWND details_window{};
constexpr int details_text_id=401, details_copy_id=402, details_close_id=403;
LRESULT CALLBACK details_dispatch(HWND w, UINT message, WPARAM wp, LPARAM lp) {
    switch(message){
    case WM_CREATE: {
        auto instance=reinterpret_cast<LPCREATESTRUCTW>(lp)->hInstance;
        auto child=[&](const wchar_t* cls,const wchar_t* label,DWORD style,int id) {
            auto control=CreateWindowExW(id==details_text_id?WS_EX_CLIENTEDGE:0,cls,label,
                WS_CHILD|WS_VISIBLE|WS_TABSTOP|style,0,0,1,1,w,reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),instance,nullptr);
            SendMessageW(control,WM_SETFONT,reinterpret_cast<WPARAM>(GetStockObject(DEFAULT_GUI_FONT)),TRUE);
            return control;
        };
        child(L"EDIT",L"",ES_MULTILINE|ES_READONLY|ES_AUTOVSCROLL|WS_VSCROLL,details_text_id);
        child(L"BUTTON",L"Kopiuj całość",BS_PUSHBUTTON,details_copy_id);
        child(L"BUTTON",L"Zamknij",BS_PUSHBUTTON,details_close_id);
        return 0;
    }
    case WM_SIZE: {
        int width=LOWORD(lp),height=HIWORD(lp),dpi=GetDpiForWindow(w);
        int gap=MulDiv(16,dpi,96),button=MulDiv(128,dpi,96),row=MulDiv(34,dpi,96);
        MoveWindow(GetDlgItem(w,details_text_id),gap,gap,std::max(1,width-2*gap),std::max(1,height-row-3*gap),TRUE);
        MoveWindow(GetDlgItem(w,details_copy_id),gap,height-gap-row,button,row,TRUE);
        MoveWindow(GetDlgItem(w,details_close_id),width-gap-button,height-gap-row,button,row,TRUE);
        return 0;
    }
    case WM_NEXTDLGCTL: {
        auto next=lp?reinterpret_cast<HWND>(wp):GetNextDlgTabItem(w,GetFocus(),wp!=0);
        if(next && IsChild(w,next))SetFocus(next);
        return 0;
    }
    case WM_COMMAND:
        if(LOWORD(wp)==details_copy_id){
            auto edit=GetDlgItem(w,details_text_id);
            SendMessageW(edit,EM_SETSEL,0,-1);
            SendMessageW(edit,WM_COPY,0,0);
            SetFocus(edit);
            return 0;
        }
        if(LOWORD(wp)==details_close_id || LOWORD(wp)==IDCANCEL){DestroyWindow(w);return 0;}
        break;
    case WM_DESTROY:details_window=nullptr;return 0;
    }
    return DefWindowProcW(w,message,wp,lp);
}
void show_details(HWND parent, const std::wstring& title, const std::wstring& details) {
    auto instance=GetModuleHandleW(nullptr);
    if(!details_window){
        constexpr wchar_t class_name[]=L"VipNetDetailsWindow";
        WNDCLASSW cls{};cls.hInstance=instance;cls.lpszClassName=class_name;cls.lpfnWndProc=details_dispatch;
        cls.hCursor=LoadCursorW(nullptr,IDC_ARROW);cls.hbrBackground=GetSysColorBrush(COLOR_BTNFACE);
        if(!RegisterClassW(&cls) && GetLastError()!=ERROR_CLASS_ALREADY_EXISTS)return;
        MONITORINFO monitor{};monitor.cbSize=sizeof monitor;
        if(!GetMonitorInfoW(MonitorFromWindow(parent,MONITOR_DEFAULTTONEAREST),&monitor))return;
        auto area=monitor.rcWork;int dpi=GetDpiForWindow(parent);
        int width=std::min<int>(area.right-area.left,MulDiv(780,dpi,96));
        int height=std::min<int>(area.bottom-area.top,MulDiv(510,dpi,96));
        details_window=CreateWindowExW(WS_EX_CONTROLPARENT,class_name,title.c_str(),WS_OVERLAPPEDWINDOW|WS_CLIPCHILDREN,
            area.left+(area.right-area.left-width)/2,area.top+(area.bottom-area.top-height)/2,width,height,parent,nullptr,instance,nullptr);
    }
    if(!details_window)return;
    SetWindowTextW(details_window,title.c_str());
    auto edit=GetDlgItem(details_window,details_text_id);
    SetWindowTextW(edit,details.c_str());
    ShowWindow(details_window,SW_RESTORE);SetForegroundWindow(details_window);SetFocus(edit);
    SendMessageW(edit,EM_SETSEL,0,0);
}
std::wstring selected_row_text() {
    auto index=view.selected();
    const auto& page=view.table_data();
    if(index<0 || static_cast<size_t>(index)>=page.rows.size())return {};
    const auto& row=page.rows[index];
    std::wstring text;
    for(size_t i=0;i<std::min(row.cells.size(),page.columns.size());++i)
        text+=page.columns[i].first+L"\t"+row.cells[i]+L"\r\n";
    if(!row.detail.empty())text+=L"\r\n"+row.detail;
    return text;
}
void show_report(HWND w,bool raw) {
    report_open=true;technical=raw;
    view.details(10,raw?L"Raport techniczny":L"Raport z pomiaru",raw?technical_text:result_text);
    SetWindowTextW(GetDlgItem(w,report_id),raw?L"Prosty wynik":L"Dane techniczne");
}
std::wstring control_text(HWND w,int id){
    auto item=GetDlgItem(w,id);std::wstring text(GetWindowTextLengthW(item)+1,L'\0');
    text.resize(GetWindowTextW(item,text.data(),static_cast<int>(text.size())));return text;
}
int choice(HWND w,int id){return static_cast<int>(SendDlgItemMessageW(w,id,CB_GETCURSEL,0,0));}
void set_control(HWND w,int id,const std::wstring& text){SetDlgItemTextW(w,id,text.c_str());}
Json game_catalog;
std::jthread catalog_job;
std::array<Json,3> route_reports;
Json active_samples=Json::array(),new_samples=Json::array();
std::mutex sample_mutex;
int route_mode=0;
bool active_trace=false,game_results_visible=false;
int opened_route=0;
bool catalog_loading=false;
constexpr UINT catalog_message=WM_APP+3,segment_message=WM_APP+4;
std::vector<std::wstring> favorite_hosts;
void favorites(HWND w,bool append){
    auto base=std::filesystem::path(environment(L"LOCALAPPDATA"))/L"VIP-NET"/L"Diagnostyka";
    auto path=base/(L"targets-"+hash_name(origin())+L".json");
    favorite_hosts.clear();std::ifstream f(path,std::ios::binary);
    if(f){auto doc=Json::parse(f,nullptr,false);if(doc.is_array())for(auto& v:doc)if(v.is_string() && favorite_hosts.size()<32)favorite_hosts.push_back(wide(v.get<std::string>()));f.close();}
    if(append){
        auto host=control_text(w,target_id);if(host.empty() || host.size()>253 || host.find_first_not_of(L"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-:")!=host.npos){view.route_status(L"Podaj poprawny adres celu.");return;}
        if(std::find(favorite_hosts.begin(),favorite_hosts.end(),host)==favorite_hosts.end()){
            if(favorite_hosts.size()>=32){view.route_status(L"Zapisano już 32 cele.");return;}
            favorite_hosts.push_back(host);Json out=Json::array();for(auto& v:favorite_hosts)out.push_back(utf8(v));
            std::filesystem::create_directories(base);write_atomic(path,out.dump());
        }
        view.route_status(L"Cel zapisany w ulubionych na tym komputerze.");
    }
    auto items=favorite_hosts;items.insert(items.begin(),L"Ulubione cele");view.choices(saved_id,items);
}
constexpr UINT_PTR route_timer=2;
std::wstring catalog_error;
std::filesystem::path catalog_file(){
    return std::filesystem::path(environment(L"LOCALAPPDATA"))/L"VIP-NET"/L"Diagnostyka"/(L"games-"+hash_name(origin())+L".json");
}
void start_catalog(HWND w){
    if(catalog_loading || game_catalog.is_object())return;
    catalog_loading=true;
    catalog_job=std::jthread([w,host=origin()]{
        auto result=std::make_unique<std::pair<Json,std::wstring>>();
        auto bundled=Json::parse(bundled_game_catalog);
        const auto revision=bundled.at("revision").get<int>();
        auto usable=[revision](const Json& doc){
            if(!doc.is_object() || doc.value("version",0)!=1 || doc.value("revision",0)<revision ||
               !doc.contains("profiles") || !doc["profiles"].is_array() || doc["profiles"].empty() || doc["profiles"].size()>64) return false;
            for(const auto& game:doc["profiles"]){
                if(!game.is_object() || !field(game,"name").is_string() || !field(game,"processes").is_array() || !field(game,"regions").is_array()) return false;
                for(const auto& region:game.at("regions")){
                    if(!region.is_object()) return false;
                    for(const char* key:{"host","label","kind","verified","source"})
                        if(!field(region,key).is_string()) return false;
                    if(region["kind"]=="session_relay" || region["kind"]=="session_server") return false;
                }
            }
            return true;
        };
        try{
            auto online=fetch_game_profiles(host);
            if(!usable(online)) throw std::runtime_error("older_catalog");
            result->first=std::move(online);
            try {
                auto path=catalog_file();std::filesystem::create_directories(path.parent_path());
                write_atomic(path,result->first.dump());
            } catch(const std::exception&) {}
        }catch(const std::exception&){
            result->first=std::move(bundled);
            result->second=L"Katalog dołączony do aplikacji.";
            try {
                std::ifstream cached(catalog_file(),std::ios::binary);
                auto prior=Json::parse(cached,nullptr,false);
                if(usable(prior)){
                    result->first=std::move(prior);
                    result->second=L"Katalog z ostatniego połączenia.";
                }
            } catch(const std::exception&) {}
        }
        if(PostMessageW(w,catalog_message,0,reinterpret_cast<LPARAM>(result.get())))result.release();
    });
}
bool game_running(const Json& names){
    HANDLE handle=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if(handle==INVALID_HANDLE_VALUE)return false;
    PROCESSENTRY32W entry{};entry.dwSize=sizeof entry;bool found=false;
    if(Process32FirstW(handle,&entry))do{
        for(const auto& n:names)if(n.is_string() && !_wcsicmp(wide(n.get<std::string>()).c_str(),entry.szExeFile)){found=true;break;}
    }while(!found && Process32NextW(handle,&entry));
    CloseHandle(handle);return found;
}
std::filesystem::path league_logs(){
    auto fallback=std::filesystem::path(environment(L"SystemDrive")+L"\\Riot Games\\League of Legends\\Logs\\GameLogs");
    HANDLE snapshot=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if(snapshot==INVALID_HANDLE_VALUE) return fallback;
    PROCESSENTRY32W p{};p.dwSize=sizeof p;
    if(Process32FirstW(snapshot,&p)) do {
        if(_wcsicmp(p.szExeFile,L"League of Legends.exe")!=0) continue;
        HANDLE game=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,p.th32ProcessID);
        if(!game) continue;
        std::wstring image(32768,L'\0');DWORD length=static_cast<DWORD>(image.size());
        if(QueryFullProcessImageNameW(game,0,image.data(),&length)){
            image.resize(length);
            fallback=std::filesystem::path(image).parent_path().parent_path()/L"Logs"/L"GameLogs";
        }
        CloseHandle(game);
        break;
    }while(Process32NextW(snapshot,&p));
    CloseHandle(snapshot);
    return fallback;
}
const Json& selected_game(HWND w){
    const auto& profiles=field(game_catalog,"profiles");auto i=choice(w,choice_id);
    static const Json empty;
    return profiles.is_array() && i>=0 && static_cast<size_t>(i)<profiles.size()?profiles[i]:empty;
}
std::wstring target_description(const std::string& kind){
    if(kind=="game_server") return L"Adres, pod którym można dołączyć do gry. Test mierzy czas odpowiedzi ICMP.";
    if(kind=="steam_relay") return L"Przekaźnik Steam. Pomiar obejmuje drogę do przekaźnika.";
    if(kind=="session_server") return L"Serwer meczu, z którym League of Legends połączyło się na tym komputerze w ostatnich 24 godzinach.";
    if(kind=="session_relay") return L"Przekaźnik użyty przez Roblox na tym komputerze w ostatnich 24 godzinach.";
    if(kind=="game_service") return L"Usługa wskazana w profilu. Ping podczas rozgrywki może być inny.";
    if(kind=="network_probe") return L"Punkt pomiarowy w sieci dostawcy. Wynik dotyczy drogi do tego punktu.";
    return L"Regionalny adres diagnostyczny wskazany przez wydawcę.";
}
void game_region(HWND w){
    EnableWindow(GetDlgItem(w,target_id),!busy);
    const auto& g=selected_game(w);auto& regions=field(g,"regions");int i=choice(w,region_id);
    if(regions.is_array() && i>=0 && static_cast<size_t>(i)<regions.size()){
        auto& r=regions[i];set_control(w,target_id,wide(r.value("host","")));SendDlgItemMessageW(w,target_id,EM_SETREADONLY,TRUE,0);
        view.route_status(target_description(r.value("kind","")));
    }else{set_control(w,target_id,L"");SendDlgItemMessageW(w,target_id,EM_SETREADONLY,FALSE,0);view.route_status(catalog_error.empty()?L"Podaj własny cel dla wybranego profilu.":catalog_error);}
}
void game_selection(HWND w){
    auto index=choice(w,choice_id);
    if(game_catalog.is_object() && index>=0 && static_cast<size_t>(index)<game_catalog.at("profiles").size()){
        auto& game=game_catalog["profiles"][index];
        auto name=game.value("name","");
        if(name=="Roblox" || name=="League of Legends"){
            bool roblox=name=="Roblox";
            std::string kind=roblox?"session_relay":"session_server";
            auto& rows=game.at("regions");
            rows.erase(std::remove_if(rows.begin(),rows.end(),[&](const Json& r){return r.value("kind","")==kind;}),rows.end());
            auto now=std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now());
            std::optional<GameRelay> recent;
            if(roblox){
                auto base=environment(L"LOCALAPPDATA");
                if(!base.empty()) recent=recent_roblox_relay(std::filesystem::path(base)/L"Roblox"/L"logs",now);
            }else recent=recent_league_match(league_logs(),now);
            if(recent) rows.insert(rows.begin(),Json{{"label",roblox?"Przekaźnik ostatniej gry Roblox":"Serwer ostatniego meczu LoL"},
                {"host",recent->host},{"method","icmp"},{"kind",kind},{"verified",recent->utc},{"source","dziennik gry na tym komputerze"}});
        }
    }
    auto& g=selected_game(w);std::vector<std::wstring> regions;
    for(const auto& r:field(g,"regions"))regions.push_back(wide(r.value("label","")));
    regions.push_back(L"Własny cel");
    view.choices(region_id,regions);game_region(w);
}
void init_games(HWND w){
    std::vector<std::wstring> names;
    for(const auto& g:field(game_catalog,"profiles"))if(g.is_object())names.push_back(wide(g.value("name","")));
    if(names.empty())names.push_back(L"Własny profil");
    view.choices(choice_id,names);game_selection(w);
}
DetailPage route_display(int page,const Json& doc){
    auto p=page==7 || field(field(doc,"measurement"),"technique")=="trace"?route_page(field(doc,"mtr_samples")):ping_page(field(doc,"mtr_samples"));
    if(doc.is_object() && doc.contains("state")){
        auto m=field(doc,"measurement");
        auto state=doc.value("state","");auto prefix=state=="completed"?L"Zakończono":state=="cancelled"?L"Zatrzymano":L"Pomiar częściowy";
        p.subtitle=std::wstring(prefix)+L" · "+wide(m.value("target_name",""))+L" · "+(doc.value("synchronized",false)?L"zapisano w panelu":L"zapis lokalny");
    }else if(p.rows.empty())p.subtitle=page==7?L"Podaj cel i uruchom pomiar trasy.":page==8?L"Podaj cel i wybierz czas obserwacji.":L"Wybierz grę i cel pomiaru lub wpisz własny adres.";
    return p;
}
void bind_result(const Json& doc){
    if(!doc.is_object()){view.report_source(L"Brak pomiaru w tym widoku",false);return;}
    bool synced=doc.value("synchronized",false);
    view.report_source(synced?L"Serwer potwierdził zapis tej sesji":L"Zapis lokalny · oczekuje na synchronizację",true);
}
void route_report(HWND w,int mode,bool raw){
    const auto& doc=route_reports[mode-6];if(!doc.is_object())return;
    opened_route=mode;report_open=true;technical=raw;
    const auto& m=doc.at("measurement");auto p=route_display(mode,doc);
    std::wostringstream out;
    out<<wide(m.value("profile_name",""))<<L" · "<<wide(m.value("target_name",""))<<L"\r\n"<<p.subtitle<<L"\r\n";
    for(const auto& ip:field(m,"targets")) if(ip.is_string())out<<L"Adres IP użyty w teście · "<<wide(ip.get<std::string>())<<L"\\r\\n";
    out<<L"Rozpoczęcie UTC · "<<wide(doc.value("started_at",""))<<L"\r\nZakończenie UTC · "<<wide(doc.value("ended_at",""))<<L"\r\n\r\n";
    if(raw)out<<wide(doc.dump(2));
    else for(const auto& row:p.rows){
        if(row.cells.size()>=2)out<<row.cells[0]<<L"   "<<row.cells[1]<<L"\r\n";
        out<<row.detail<<L"\r\n\r\n";
    }
    view.details(10,raw?L"Dane techniczne sesji":L"Raport z diagnostyki",out.str());bind_result(doc);
    set_control(w,report_id,raw?L"Prosty wynik":L"Dane techniczne");
}
void show_profiles_info(HWND w){
    if(route_mode)return;
    game_results_visible=false;bind_result(nullptr);
    auto& g=selected_game(w);if(!g.is_object())return;
    DetailPage p{L"Wybierz grę i cel pomiaru.",{{L"Profil",200},{L"Status lub cel",400}},{}};
    auto name=wide(g.value("name",""));
    bool running=game_running(field(g,"processes"));
    p.rows.push_back({{name,running?L"Rozpoznano uruchomiony proces":L"Brak potwierdzonego procesu"},L"Dopasowanie nazwy procesu w Windows. Aktywny serwer meczu pozostaje nieustalony.",{},{}});
    for(const auto& r:field(g,"regions"))
        p.rows.push_back({{wide(r.value("label","")),wide(r.value("host",""))},target_description(r.value("kind",""))+L" Weryfikacja "+wide(r.value("verified",""))+L" · "+wide(r.value("source","")),{},{}});
    if(name==L"Roblox" && std::none_of(field(g,"regions").begin(),field(g,"regions").end(),
        [](const Json& r){return r.value("kind","")=="session_relay";}))
        p.rows.push_back({{L"Ostatnia gra",L"Brak świeżego adresu przekaźnika"},L"Po dołączeniu do gry w aplikacji Roblox na Windows wybierz profil ponownie. Adres jest dostępny przez 24 godziny, jeśli Roblox zapisze go w swoim dzienniku.",{},{}});
    if(name==L"League of Legends" && std::none_of(field(g,"regions").begin(),field(g,"regions").end(),
        [](const Json& r){return r.value("kind","")=="session_server";}))
        p.rows.push_back({{L"Ostatni mecz",L"Brak świeżego adresu meczu"},L"Po dołączeniu do meczu wybierz profil ponownie. Przy instalacji poza domyślnym katalogiem pozostaw grę uruchomioną.",{},{}});
    if(p.rows.size()==1)p.rows.push_back({{L"Host regionalny",L"Brak zweryfikowanego celu"},L"Możesz podać pojedynczy adres otrzymany od operatora gry.",{},{}});
    view.table(std::move(p));game_region(w);
}
constexpr UINT update_message=WM_APP+5;
std::jthread update_job;
std::optional<updates::Release> offered_release;
std::wstring update_status=L"Sprawdzanie dostępnej wersji…";
bool updating=false, installed_update=false;
struct UpdateResult {
    std::optional<updates::Release> available;
    std::wstring status;
    bool installed=false;
};
UpdateResult update_result;
void start_update(HWND w,bool install){
    if(updating || installed_update)return;
    updating=true;
    update_status=install?L"Pobieranie i weryfikacja pliku…":L"Sprawdzanie dostępnej wersji…";
    auto previous=offered_release;
    update_job=std::jthread([w,install,previous,host=origin()]{
        UpdateResult result;
        try{
            auto release=updates::check(host);
            if(updates::newer(release.version,utf8(desktop_version))){
                result.available=release;
                if(install && previous && previous->sha256==release.sha256 && previous->version==release.version){
                    updates::install(release,host);
                    result.installed=true;
                    result.status=L"Pobrano i zweryfikowano "+wide(release.version)+L". Zamknij aplikację, aby dokończyć instalację.";
                }else result.status=L"Dostępna wersja "+wide(release.version)+L". Wybierz przycisk aktualizacji.";
            }else result.status=L"Masz aktualną wersję aplikacji.";
        }catch(const std::exception& e){result.status=L"Nie udało się ukończyć aktualizacji. "+wide(e.what());}
        update_result=std::move(result);
        PostMessageW(w,update_message,0,0);
    });
}
constexpr UINT live_message=WM_APP+6;
std::jthread live_job;
int live_active{},live_requested{};
void refresh_live(HWND w, int page) {
    live_requested=page;
    if(live_active)return;
    live_active=page;
    EnableWindow(GetDlgItem(w,refresh_live_id),FALSE);
    view.route_status(L"Odczytywanie bieżących danych Windows…");
    auto previous=detail_page(page,last_report,view.data());
    live_job=std::jthread([w,page,previous=std::move(previous)]{
        auto result=std::make_unique<DetailPage>();
        try {*result=page==2?live_computer(previous):live_lan();}
        catch(const std::exception&){
            *result=previous;
            result->subtitle=L"Windows nie udostępnił bieżącego odczytu.";
        }
        if(PostMessageW(w,live_message,page,reinterpret_cast<LPARAM>(result.get())))result.release();
    });
}
void navigate(HWND w,int page){
    report_open=false;opened_route=0;
    if(!page){view.home();view.controls(busy,!code.empty(),!technical_text.empty());set_control(w,report_id,L"Pełny raport");return;}
    auto p=page==2 && process_capture?process_capture->page(false,L""):detail_page(page,last_report,view.data());
    if(page>=6 && page<=8){
        auto& doc=route_reports[page-6];
        p=route_display(page,!doc.is_object() && page==7?last_report:doc);
        if(route_mode==page)p=active_trace?route_page(active_samples):ping_page(active_samples);
    }else if(page==9 || page==10){
        const bool history=page==9;
        p.columns=history?
            decltype(p.columns){{L"Czas rozpoczęcia UTC",194},{L"Test",142},{L"Sesja",220},{L"Stan",132},{L"Cel",175}}:
            decltype(p.columns){{L"Czas rozpoczęcia UTC",194},{L"Raport",142},{L"Sesja",220},{L"Pobieranie",98},{L"Wysyłanie",98},{L"Ping / próbki",105}};
        p.subtitle=history?L"Dziennik wykonanych i przerwanych prób. Enter otwiera zapis.":L"Zestawienie wyników zapisanych raportów. Enter otwiera raport.";
        if(!code.empty()){
            auto dir=profile(origin(),code)/L"reports";std::error_code ec;
            for(const auto& file:std::filesystem::directory_iterator(dir,ec)){
                if(file.path().extension()!=L".json")continue;
                std::ifstream input(file.path(),std::ios::binary);auto doc=Json::parse(input,nullptr,false);if(!doc.is_object())continue;
                const auto& t=doc.contains("throughput")?doc.at("throughput"):doc;
                auto id=t.value("session_id","");if(id.empty())continue;
                const auto& m=field(doc,"measurement");std::wstring kind=L"Pełny test";if(m.is_object())kind=wide(m.value("profile_name",m.value("purpose","")));
                DetailRow row;
                row.cells={wide(t.value("started_at","")),kind,wide(id)};
                if(history){
                    const auto& archived_state=field(doc,"state");
                    const auto& pings=field(t,"host_pings");
                    auto legacy_cancelled=field(t,"error")=="cancelled" || field(field(pings,"gateway"),"reason")=="cancelled" ||
                        field(field(pings,"node"),"reason")=="cancelled";
                    bool cancelled_report=archived_state=="cancelled" || (archived_state.is_null() && legacy_cancelled);
                    bool completed=archived_state=="completed" || (archived_state.is_null() && doc.contains("throughput") &&
                        !summary::read(doc).partial);
                    auto state=cancelled_report?L"Przerwano":completed?L"Zakończono":L"Częściowy";
                    auto target=field(m,"target_name").is_string()?field(m,"target_name"):field(t,"peer");
                    row.cells.insert(row.cells.end(),{state,target.is_string()?wide(target.get<std::string>()):L"—"});
                }else if(doc.contains("throughput")){
                    auto saved=summary::read(doc);
                    auto with_unit=[&](int index,const wchar_t* unit){
                        const auto& v=saved.metrics[index].value;
                        return v==L"—"?v:v+unit;
                    };
                    row.cells.insert(row.cells.end(),{with_unit(0,L" Mb/s"),with_unit(1,L" Mb/s"),with_unit(2,L" ms")});
                }else{
                    auto count=field(doc,"mtr_samples").size();
                    row.cells.insert(row.cells.end(),{L"—",L"—",std::to_wstring(count)+L" próbek"});
                }
                row.detail=doc.value("synchronized",false)?L"Serwer potwierdził synchronizację raportu.":L"Zapis lokalny w profilu komputera.";
                p.rows.push_back(std::move(row));
            }
            std::sort(p.rows.begin(),p.rows.end(),[](const auto& a,const auto& b){return a.cells[0]>b.cells[0];});
        }
    }else if(page==11){
        p.subtitle=L"Konfiguracja tej kopii programu";
        p.rows={{{L"Serwer pomiarowy",origin()},L"Adres HTTPS z konfiguracji NetDiagnostics.ini lub z ustawień tej dystrybucji.",{},{}},
            {{L"Profil pomiaru",view.capacity()?L"Pełna prędkość":L"Mały transfer"},L"Profil następnego testu wybierzesz na ekranie Podsumowanie.",{},{}},
            {{L"Wersja Windows EXE",desktop_version},L"Wersja binarium uruchomionego na tym komputerze.",{},{}},
            {{L"Aktualizacja aplikacji",update_status},L"Program sprawdza wersję przy otwarciu. Pobieranie nowej wersji wymaga kliknięcia.",{},{}},
            {{L"Panel klienta",origin()+L"/klient"},L"Przycisk na dole kopiuje prywatny kod do panelu klienta.",{},{}}};
    }
    view.workspace(page,std::move(p));
    if((page==2 && !process_capture) || page==3)refresh_live(w,page);

    if(page==11){
        set_control(w,update_id,installed_update?L"Zamknij i zastosuj":offered_release?L"Zainstaluj aktualizację":L"Sprawdź aktualizacje");
        EnableWindow(GetDlgItem(w,update_id),!updating && !busy && !loading);
    }
    set_control(w,report_id,L"Pełny raport");
    if(page<6 || page>8){view.controls(busy,!code.empty(),!technical_text.empty());return;}
    if(route_reports[page-6].is_object())bind_result(route_reports[page-6]);else if(page!=7 || !last_report.is_object())bind_result(nullptr);else view.controls(busy,!code.empty(),!technical_text.empty());
    if(page==6){game_results_visible=route_reports[0].is_object();start_catalog(w);init_games(w);if(!route_reports[0].is_object())show_profiles_info(w);}
    else{
        view.choices(mode_id,page==7?std::vector<std::wstring>{L"ICMP",L"TCP 443"}:std::vector<std::wstring>{L"Ping ICMP"});
        view.choices(choice_id,page==7?std::vector<std::wstring>{L"20 przebiegów",L"100 przebiegów",L"300 przebiegów"}:
            std::vector<std::wstring>{L"1 minuta",L"5 minut",L"15 minut",L"30 minut",L"60 minut",L"Do zatrzymania"});
        SendDlgItemMessageW(w,target_id,EM_SETREADONLY,FALSE,0);
        if(page==7)favorites(w,false);
        auto& peer=field(field(last_report,"throughput"),"peer");set_control(w,target_id,peer.is_string()?wide(peer.get<std::string>()):L"");
    }
    view.route_controls(!busy && !loading);
    if(page==6 && !busy){game_region(w);if(route_reports[0].is_object())view.route_status(route_display(6,route_reports[0]).subtitle); }
    EnableWindow(GetDlgItem(w,action_id),route_mode==page || (!busy && !loading));
}
void launch_route(HWND w){
    auto page=view.page();
    if(page<6 || page>8 || busy || loading)return;
    RouteRequest r;
    r.host=utf8(control_text(w,target_id));
    if(r.host.empty()){view.route_status(L"Wpisz pojedynczy adres IP lub nazwę DNS.");SetFocus(GetDlgItem(w,target_id));return;}
    r.purpose=page==6?"gaming":page==7?"mtr":"monitor";r.profile=page==6?utf8(control_text(w,choice_id)):page==7?"MTR":"Monitoring";
    r.protocol=page==7 && choice(w,mode_id)==1?"tcp":"icmp";r.direct=page!=7;
    const bool continuous=page==8 && choice(w,choice_id)==5;
    if(page==7){
        r.family=choice(w,family_id)==1?4:choice(w,family_id)==2?6:0;
        constexpr unsigned rounds[]={20,100,300},hops[]={8,16,32},intervals[]={100,500,1000};
        r.attempts=rounds[std::clamp(choice(w,choice_id),0,2)];r.ttl=hops[std::clamp(choice(w,limit_id),0,2)];r.interval=intervals[std::clamp(choice(w,interval_id),0,2)];
    }else{
        constexpr unsigned lengths[]={60,300,900,1800,3600};
        r.attempts=page==6?20:continuous?300:lengths[std::clamp(choice(w,choice_id),0,4)];r.ttl=64;r.interval=1000;
    }
    if(page==6){
        const auto& regions=field(selected_game(w),"regions");int index=choice(w,region_id);
        if(regions.is_array() && index>=0 && static_cast<size_t>(index)<regions.size()){
            r.region=regions[index].value("label","");r.target_kind=regions[index].value("kind","official_diagnostic");
        }
        constexpr unsigned rounds[]={20,100,300};r.attempts=rounds[std::clamp(choice(w,game_length_id),0,2)];
        if(choice(w,game_method_id)==1){r.direct=false;r.ttl=16;r.interval=100;}
    }
    active_trace=!r.direct;busy=true;cancelled=false;route_mode=page;worker_error.clear();worker_report=nullptr;active_samples=Json::array();new_samples=Json::array();
    view.table(active_trace?route_page(active_samples):ping_page(active_samples));view.route_controls(false);view.controls(true,false,false);
    view.report_source(L"Pomiar w toku",false);view.route_status(L"Ustalanie adresu celu…");SetTimer(w,route_timer,400,nullptr);
    for(int i=0;i<12;++i)EnableWindow(GetDlgItem(w,nav_id+i),FALSE);
    EnableWindow(GetDlgItem(w,back_id),FALSE);
    job=std::jthread([w,r,continuous]{
        try{
            auto host=origin();code=credential(host,true);auto dir=profile(host,code);
            SetEnvironmentVariableW(L"VIPNET_API_ORIGIN",host.c_str());SetEnvironmentVariableW(L"VIPNET_TOKEN",code.c_str());
            SetEnvironmentVariableW(L"VIPNET_QUEUE_DIR",dir.c_str());
            do{
                worker_report=run_route(r,cancelled,[](const Json& sample){std::scoped_lock lock(sample_mutex);new_samples.push_back(sample);});
                auto archive=dir/L"reports";std::filesystem::create_directories(archive);
                auto bytes=worker_report.dump();write_atomic(archive/(worker_report.at("session_id").get<std::string>()+".json"),bytes);
                write_atomic(dir/("last-"+r.purpose+".json"),bytes);
                if(!continuous || cancelled || worker_report.at("state")!="completed")break;
                SendMessageW(w,segment_message,0,0);
            }while(!cancelled);
        }catch(const std::exception& e){worker_error=wide(e.what());}
        PostMessageW(w,done_message,0,0);
    });
}
void open_archive(HWND w){
    int index=view.selected();const auto& p=view.table_data();
    if(index<0 || static_cast<size_t>(index)>=p.rows.size() || code.empty())return;
    auto dir=profile(origin(),code)/L"reports";
    auto name=p.rows[index].cells.at(2);if(name.size()!=36 || name.find_first_not_of(L"0123456789abcdefABCDEF-")!=name.npos)return;
    std::ifstream input(dir/(name+L".json"),std::ios::binary);auto doc=Json::parse(input,nullptr,false);
    if(!doc.is_object())return;
    if(doc.contains("throughput")){
        show_details(w,L"Archiwalny raport z pomiaru",wide(reader_report(doc)));
    }else if(field(doc,"measurement").is_object()){
        auto type=doc.at("measurement").value("purpose","");int mode=type=="gaming"?6:type=="monitor"?8:7;
        route_reports[mode-6]=std::move(doc);navigate(w,mode);
    }
}
void compare_route(HWND w){
    const auto& current=route_reports[1];
    if(!current.is_object() || code.empty()){view.route_status(L"Wykonaj samodzielny MTR, aby porównać zapisane trasy.");return;}
    const auto& setup=current.at("measurement");Json previous;
    auto dir=profile(origin(),code)/L"reports";std::error_code ec;
    for(const auto& f:std::filesystem::directory_iterator(dir,ec)){
        if(f.path().extension()!=L".json")continue;
        std::ifstream input(f.path(),std::ios::binary);auto doc=Json::parse(input,nullptr,false);
        auto& m=field(doc,"measurement");if(!m.is_object() || field(m,"purpose")!="mtr")continue;
        bool same=true;for(auto key:{"targets","protocol","max_ttl","timeout_ms","interval_ms","attempts"})
            if(field(m,key)!=field(setup,key))same=false;
        if(same && field(doc,"started_at")<current.at("started_at") && (!previous.is_object() || doc.at("started_at")>previous.at("started_at")))previous=std::move(doc);
    }
    if(!previous.is_object()){view.route_status(L"Brak wcześniejszego MTR do tego adresu z tymi samymi parametrami.");return;}
    DetailPage p{L"Porównanie z pomiarem · "+wide(previous.value("started_at",""))+L" UTC",{
        {L"Skok",55},{L"Router wcześniej",148},{L"Router obecnie",148},{L"P95 wcześniej",100},{L"P95 obecnie",96},{L"Brak wcześniej (%)",125},{L"Brak obecnie (%)",120}},{}};
    std::map<int,std::array<std::vector<std::wstring>,2>> by_ttl;
    auto add=[&](const Json& doc,size_t n){for(auto& r:route_page(doc.at("mtr_samples")).rows)by_ttl[std::stoi(r.cells[0])][n]=std::move(r.cells);};
    add(previous,0);add(current,1);
    for(auto& [ttl,pair]:by_ttl){
        auto get=[&](size_t n,size_t i){return pair[n].empty()?std::wstring(L"—"):pair[n][i];};
        p.rows.push_back({{std::to_wstring(ttl),get(0,1),get(1,1),get(0,13),get(1,13),get(0,7),get(1,7)},
            L"P95 w milisekundach. Adresy wskazują routery, które odpowiedziały w każdej sesji. Brak odczytu oznaczono kreską.",{},{}});
    }
    view.table(std::move(p));set_control(w,report_id,L"Pełny raport");
}
void export_page(HWND w){
    const auto& p=view.table_data();if(p.rows.empty())return;
    wchar_t dest[32768]=L"NetDiagnostics";OPENFILENAMEW dialog{sizeof dialog};dialog.hwndOwner=w;dialog.lpstrFile=dest;dialog.nMaxFile=32768;
    dialog.lpstrFilter=L"Tabela CSV UTF-8\0*.csv\0Raport JSON\0*.json\0Tabela tekstowa\0*.txt\0";dialog.lpstrDefExt=L"csv";dialog.Flags=OFN_OVERWRITEPROMPT|OFN_PATHMUSTEXIST|OFN_NOCHANGEDIR;
    if(!GetSaveFileNameW(&dialog))return;
    try{
        auto n=view.page();Json doc=last_report;if(n>=6 && n<=8 && route_reports[n-6].is_object())doc=route_reports[n-6];
        if(n==6 && !game_results_visible)doc=nullptr;
        std::vector<std::vector<std::wstring>> rows(1);for(const auto& col:p.columns)rows.front().push_back(col.first);
        for(const auto& r:p.rows)rows.push_back(r.cells);
        std::string bytes;
        if(dialog.nFilterIndex==2){
            Json table=Json::array();for(auto& row:rows){Json cells=Json::array();for(auto& c:row)cells.push_back(utf8(c));table.push_back(std::move(cells));}
            bytes=Json{{"view",n},{"table",table},{"report",n==9 || n==10 || n==11?Json(nullptr):doc}}.dump(2);
        }else{
            bytes="\xef\xbb\xbf";bool csv=dialog.nFilterIndex==1;
            for(auto& row:rows){bool first=true;for(auto& cell:row){
                if(!first)bytes+=csv?";":"\t";first=false;auto txt=utf8(cell);
                if(csv){
                    const auto first_text=txt.find_first_not_of(" \t\r\n");
                    if(first_text!=std::string::npos && std::string_view("=+-@").find(txt[first_text])!=std::string_view::npos)
                        txt.insert(0,1,'\'');
                    bytes+='"';for(char c:txt){if(c=='"')bytes+='"';bytes+=c;}bytes+='"';}else bytes+=txt;
            }bytes+="\r\n";}
        }
        write_atomic(dest,bytes);view.route_status(L"Plik zapisany.");
    }catch(const std::exception& e){view.route_status(L"Błąd zapisu · "+wide(e.what()));}
}
void load_report(HWND w) {
    loading=true;
    for(int i=0;i<12;++i)EnableWindow(GetDlgItem(w,nav_id+i),FALSE);
    EnableWindow(GetDlgItem(w,start_id),FALSE);
    view.phase(L"Odczytywanie ostatniego raportu…");
    job=std::jthread([w]{
        try {
            auto host=origin();
            if(!host.empty()) code=credential(host,false);
            if(!code.empty()) {
                std::ifstream file(profile(host,code)/L"last-report.json",std::ios::binary);
                if(file) worker_report=Json::parse(file);
                int i=0;
                for(auto name:{"gaming","mtr","monitor"}){
                    std::ifstream route(profile(host,code)/(std::string("last-")+name+".json"),std::ios::binary);
                    if(route){auto d=Json::parse(route,nullptr,false);if(d.is_object())route_reports[i]=std::move(d);}
                    ++i;
                }
            }
        } catch(const std::exception& e) {worker_error=wide(e.what());}
        PostMessageW(w,done_message,0,0);
    });
}
void save_placement(HWND w) {
    WINDOWPLACEMENT p{};p.length=sizeof p;
    if (GetWindowPlacement(w,&p)) {
        if (p.showCmd!=SW_SHOWMAXIMIZED) p.showCmd=SW_SHOWNORMAL;
        RegSetKeyValueW(HKEY_CURRENT_USER,placement_key,L"Window",REG_BINARY,&p,sizeof p);
    }
}
LRESULT CALLBACK dispatch(HWND w,UINT m,WPARAM a,LPARAM b) {
    switch(m) {
    case WM_CREATE:
        set_window_icon(w,-1);view.create(w,origin(),setting(L"Operator",L"NetDiagnostics"));
        view.controls(false,false,false);load_report(w);start_update(w,false);return 0;
    case WM_GETMINMAXINFO: {
        auto lim=reinterpret_cast<MINMAXINFO*>(b);auto dpi=GetDpiForWindow(w);if(!dpi)dpi=96;
        MONITORINFO mon{sizeof mon};
        GetMonitorInfoW(MonitorFromWindow(w,MONITOR_DEFAULTTONEAREST),&mon);
        lim->ptMinTrackSize={std::min<LONG>(MulDiv(960,dpi,96),mon.rcWork.right-mon.rcWork.left),
                             std::min<LONG>(MulDiv(640,dpi,96),mon.rcWork.bottom-mon.rcWork.top)};return 0;
    }
    case WM_DPICHANGED: {
        auto r=reinterpret_cast<const RECT*>(b);view.scale(HIWORD(a));
        SetWindowPos(w,nullptr,r->left,r->top,r->right-r->left,r->bottom-r->top,SWP_NOZORDER|SWP_NOACTIVATE);return 0;
    }
    case WM_NEXTDLGCTL: {
        HWND target=b?reinterpret_cast<HWND>(a):GetNextDlgTabItem(w,GetFocus(),a!=0);
        if(target && IsChild(w,target) && IsWindowVisible(target) && IsWindowEnabled(target)) SetFocus(target);
        return 0;
    }
    case WM_VSCROLL: view.scroll(LOWORD(a));return 0;
    case WM_MOUSEWHEEL: view.scroll(GET_WHEEL_DELTA_WPARAM(a)>0?SB_LINEUP:SB_LINEDOWN);return 0;
    case WM_SIZE: if(a!=SIZE_MINIMIZED)view.layout();return 0;
    case WM_ERASEBKGND:view.background(reinterpret_cast<HDC>(a));return 1;
    case WM_CTLCOLORSTATIC: {
        auto dc=reinterpret_cast<HDC>(a);bool edit=GetDlgCtrlID(reinterpret_cast<HWND>(b))==112;
        SetBkColor(dc,edit?RGB(255,255,255):RGB(243,243,243));SetTextColor(dc,RGB(32,32,32));
        SetDCBrushColor(dc,edit?RGB(255,255,255):RGB(243,243,243));return reinterpret_cast<LRESULT>(GetStockObject(DC_BRUSH));
    }
    case segment_message:{
        active_samples=Json::array();std::scoped_lock lock(sample_mutex);new_samples=Json::array();return 0;
    }
    case WM_NOTIFY: {
        auto header=reinterpret_cast<NMHDR*>(b);
        if(header->idFrom!=list_id)break;
        if(header->code==LVN_ITEMCHANGED)view.select_row();
        if(header->code==LVN_COLUMNCLICK)view.sort(reinterpret_cast<NMLISTVIEW*>(b)->iSubItem);
        if((header->code==NM_RETURN || header->code==NM_DBLCLK) && !busy && !loading){
            if(view.page()==9 || view.page()==10)open_archive(w);
            else if(auto body=selected_row_text();!body.empty())show_details(w,L"Szczegóły pozycji",body);
        }
        return 0;
    }
    case live_message: {
        std::unique_ptr<DetailPage> result(reinterpret_cast<DetailPage*>(b));
        live_job.join();
        live_active=0;
        if(closing){if(!busy && !loading && !catalog_loading && !updating){save_placement(w);DestroyWindow(w);}return 0;}
        if(view.page()==static_cast<int>(a)){
            view.table(std::move(*result));
            EnableWindow(GetDlgItem(w,refresh_live_id),TRUE);
        }else if(view.page()==live_requested && (live_requested==2 || live_requested==3))refresh_live(w,live_requested);
        return 0;
    }
    case update_message:
        update_job.join();updating=false;
        offered_release=std::move(update_result.available);
        installed_update=update_result.installed;update_status=std::move(update_result.status);
        if(closing){if(!busy && !loading && !catalog_loading && !live_active){save_placement(w);DestroyWindow(w);}return 0;}
        if(view.page()==11)navigate(w,11);
        if(offered_release && !installed_update)SetWindowTextW(w,L"NetDiagnostics — aktualizacja dostępna w Ustawieniach");
        return 0;
    case catalog_message: {
        std::unique_ptr<std::pair<Json,std::wstring>> result(reinterpret_cast<std::pair<Json,std::wstring>*>(b));
        catalog_job.join();catalog_loading=false;
        game_catalog=std::move(result->first);catalog_error=std::move(result->second);
        if(closing && !updating && !busy && !loading && !live_active){save_placement(w);DestroyWindow(w);return 0;}
        if(view.page()==6 && !busy && !loading){init_games(w);if(!route_reports[0].is_object())show_profiles_info(w);else view.route_status(route_display(6,route_reports[0]).subtitle);EnableWindow(GetDlgItem(w,action_id),!busy && !loading);}
        return 0;
    }
    case WM_DRAWITEM:return view.draw(*reinterpret_cast<DRAWITEMSTRUCT*>(b));
    case WM_COMMAND: {
        int id=LOWORD(a);
        if(id==update_id && installed_update && !busy && !loading){PostMessageW(w,WM_CLOSE,0,0);return 0;}
        if(id==update_id && view.page()==11 && !busy && !loading){start_update(w,offered_release.has_value());navigate(w,11);return 0;}
        if(id==favorite_id && !busy){try{favorites(w,true);}catch(const std::exception& e){view.route_status(wide(e.what()));}return 0;}
        if(id==saved_id && HIWORD(a)==CBN_SELCHANGE && !busy){
            int i=choice(w,saved_id)-1;if(i>=0 && static_cast<size_t>(i)<favorite_hosts.size())set_control(w,target_id,favorite_hosts[i]);return 0;
        }
        if(id==action_id && route_mode){cancelled=true;view.route_status(L"Zatrzymywanie i zapis próbek…");return 0;}
        if(id==action_id && !route_mode){launch_route(w);return 0;}
        if(id==archive_id && !busy && !loading && (view.page()==9 || view.page()==10)){open_archive(w);return 0;}
        if(id==compare_id && !busy){compare_route(w);return 0;}
        if(id==export_id && !busy){export_page(w);return 0;}
        if(id==refresh_live_id && !busy && (view.page()==2 || view.page()==3)){refresh_live(w,view.page());return 0;}
        if(id==process_test_id && busy && process_capture){
            cancelled=true;
            view.route_status(L"Zatrzymywanie i zapis pomiaru…");
            return 0;
        }
        if(id==resource_monitor_id && view.page()==2 && !busy){
            wchar_t dir[MAX_PATH]{};
            auto len=GetSystemDirectoryW(dir,MAX_PATH);
            auto path=std::filesystem::path(dir)/L"resmon.exe";
            if(!len || len>=MAX_PATH ||
               reinterpret_cast<INT_PTR>(ShellExecuteW(w,L"open",path.c_str(),nullptr,nullptr,SW_SHOWNORMAL))<=32)
                view.route_status(L"Windows nie otworzył Monitora zasobów.");
            return 0;
        }
        if(id==copy_row_id && !busy){
            auto body=selected_row_text();
            if(!body.empty())view.route_status(copy_text(w,body)?L"Skopiowano zaznaczony wiersz":L"Schowek jest niedostępny");
            return 0;
        }
        if(view.page()==6 && !route_mode && HIWORD(a)==CBN_SELCHANGE){
            if(id==choice_id){game_selection(w);show_profiles_info(w);}
            if(id==region_id){show_profiles_info(w);game_region(w);}
        }
        if(id==start_id && !busy && !loading)
            run(w,SendDlgItemMessageW(w,process_option_id,BM_GETCHECK,0,0)==BST_CHECKED);
        else if(id==stop_id && busy) {cancelled=true;end_chart(w);view.phase(L"Zatrzymywanie pomiaru…");}
        else if(id==copy_id && !busy && !loading) {
            view.phase(copy_text(w,code)?L"Skopiowano prywatny kod klienta":L"Nie można skopiować kodu klienta");
        } else if(id==report_id && !busy && !loading){
            int mode=opened_route?opened_route:view.page();
            if(mode>=6 && mode<=8 && route_reports[mode-6].is_object())route_report(w,mode,report_open && !technical);
            else show_report(w,report_open && !technical);
        }
        else if(id==menu_id) view.toggle_rail();
        else if(id==back_id) navigate(w,0);
        else if(id>=nav_id && id<nav_id+12) navigate(w,id-nav_id);
        else if((id>=metric_id && id<metric_id+7) || (id>=check_id && id<check_id+10) || id==finding_id) {
            const auto& s=view.data();std::wstring caption,detail;
            if(id==finding_id){caption=L"Wniosek z pomiaru";detail=s.finding+L"\r\n\r\n"+s.finding_detail;}
            else {
                const auto& f=id>=check_id?s.checks[id-check_id]:s.metrics[id-metric_id];
                caption=f.label;
                static constexpr const wchar_t* units[]={L" Mb/s",L" Mb/s",L" ms",L" ms",L" %",L" ms",L" ms"};
                std::wstring unit=id>=check_id || f.value==L"—"?L"":units[id-metric_id];
                detail=f.label+L"\r\n"+f.value+unit+L"\r\n\r\n"+f.detail;
                if(id>=metric_id && id<metric_id+2 && !s.lines[id-metric_id].empty()) {
                    const auto& line=s.lines[id-metric_id];double peak=0;for(auto p:line)peak=std::max(peak,p.mbps);
                    detail+=L"\r\n\r\nOstatnia próbka: "+number(line.back().mbps)+L" Mb/s. Maksimum: "+number(peak)+L" Mb/s.";
                }
            }
            show_details(w,caption,detail);
        }
        return 0;
    }
    case WM_TIMER:
        if(a==process_timer && process_capture && busy && view.page()==2 && !cancelled){
            view.table(process_capture->page(true,process_phase));
            return 0;
        }
        if(a==route_timer && route_mode && !cancelled){
            Json batch=Json::array();{std::scoped_lock lock(sample_mutex);batch.swap(new_samples);}
            if(!batch.empty()){
                for(auto& sample:batch)active_samples.push_back(std::move(sample));
                auto p=active_trace?route_page(active_samples):ping_page(active_samples);p.subtitle=L"Pomiar w toku · zebrane próbki: "+std::to_wstring(active_samples.size());
                view.table(std::move(p));
            }
        }
        if(a==chart_timer && active_direction && !cancelled) {
            int i=active_direction-1;view.live(i,live_traffic.trace(i));
            const auto& pts=view.data().lines[i];auto cap=live_traffic.profile_bps.load()/1e6;
            if(!pts.empty() && cap>0) set_window_icon(w,static_cast<int>(std::lround(20*std::clamp(pts.back().mbps/cap,0.0,1.0))));
        }return 0;
    case phase_message:
        if(process_capture && a<labels.size())process_phase=labels[a];
        if(busy && !cancelled && a<labels.size()) {
            end_chart(w);view.phase(labels[a]);
            if(a==1 || a==2) {active_direction=static_cast<int>(a);SetTimer(w,chart_timer,200,nullptr);}
        }return 0;
    case done_message: {
        KillTimer(w,process_timer);
        job.join();bool restore=loading;loading=false;busy=false;end_chart(w);
        if(closing){if(!updating && !catalog_loading && !live_active){save_placement(w);DestroyWindow(w);}return 0;}
        if(route_mode){
            KillTimer(w,route_timer);int mode=route_mode;route_mode=0;
            for(int i=0;i<12;++i)EnableWindow(GetDlgItem(w,nav_id+i),TRUE);
            EnableWindow(GetDlgItem(w,back_id),TRUE);
            view.controls(false,!code.empty(),!technical_text.empty());view.route_controls(true);
            if(worker_report.is_object()){
                route_reports[mode-6]=std::move(worker_report);if(mode==6)game_results_visible=true;view.table(route_display(mode,route_reports[mode-6]));bind_result(route_reports[mode-6]);
            }
            if(!worker_error.empty())view.route_status(L"Pomiar lub zapis nie powiódł się · "+worker_error);
            if(mode==6 && field(selected_game(w),"regions").is_array() && choice(w,region_id)>=0 && static_cast<size_t>(choice(w,region_id))<selected_game(w).at("regions").size())SendDlgItemMessageW(w,target_id,EM_SETREADONLY,TRUE,0);
            active_samples=Json::array();new_samples=Json::array();return 0;
        }
        for(int i=0;i<12;++i)EnableWindow(GetDlgItem(w,nav_id+i),TRUE);
        auto status=std::wstring{};
        try {
            if(worker_report.is_object()) {
                result_text=wide(reader_report(worker_report));technical_text=render_technical(worker_report);
                auto snapshot=summary::read(worker_report);
                last_report=std::move(worker_report);
                if(!worker_error.empty()) {
                    snapshot.save_status=L"Błąd zapisu lokalnego";
                    status=L"Sprawdź szczegóły zapisu raportu";
                    technical_text+=L"\r\nBłąd zapisu lokalnego: "+worker_error;
                }
                view.update(snapshot);
            } else if(!worker_error.empty()) {
                status=restore?L"Poprzedni raport jest niedostępny":L"Nie udało się zakończyć testu";
                result_text=L"Sprawdź połączenie i adres serwera, a następnie powtórz test.";
                technical_text=L"Serwer: "+origin()+L"\r\nPrzyczyna: "+worker_error;
            }
        } catch(const std::exception& e) {status=L"Nie udało się odczytać raportu";technical_text=wide(e.what());}
        view.controls(false,!code.empty(),!technical_text.empty());view.phase(status);if(view.page() && !report_open)navigate(w,view.page());return 0;
    }
    case WM_CLOSE:
        if(busy || loading || catalog_loading || updating || live_active){closing=true;cancelled=true;end_chart(w);view.phase(L"Zamykanie i zapis wyniku…");}
        else {save_placement(w);DestroyWindow(w);}return 0;
    case WM_DESTROY:view.destroy();PostQuitMessage(0);return 0;
    }
    return DefWindowProcW(w,m,a,b);
}
}

int WINAPI wWinMain(HINSTANCE instance,HINSTANCE,PWSTR arguments,int show) {
    constexpr std::wstring_view finish=L"--finish-update ";
    std::wstring_view args(arguments?arguments:L"");
    if(args.starts_with(finish)){
        auto pid=args.substr(finish.size());
        if(pid.empty() || pid.size()>10 || pid.find_first_not_of(L"0123456789")!=pid.npos)return 2;
        wchar_t* end=nullptr;unsigned long number=wcstoul(pid.data(),&end,10);
        return number && !*end?updates::finish_pending_update(number):2;
    }
    constexpr std::wstring_view process_arg=L"--process-traffic ";
    if(args.starts_with(process_arg))return traffic::run_helper(args.substr(process_arg.size()));
    updates::cleanup();
    if(!SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2)) SetProcessDPIAware();
    INITCOMMONCONTROLSEX common{sizeof common,ICC_WIN95_CLASSES};InitCommonControlsEx(&common);
    WNDCLASSW cls{};cls.hInstance=instance;cls.lpszClassName=L"VipNetDiagnosticsWindow";
    cls.lpfnWndProc=dispatch;cls.hCursor=LoadCursorW(nullptr,IDC_ARROW);cls.hIcon=LoadIconW(instance,MAKEINTRESOURCEW(1));
    if(!RegisterClassW(&cls))return 1;
    RECT work{};SystemParametersInfoW(SPI_GETWORKAREA,0,&work,0);
    int dpi=GetDpiForSystem(),width=std::min<LONG>(MulDiv(1200,dpi,96),work.right-work.left),
        height=std::min<LONG>(MulDiv(800,dpi,96),work.bottom-work.top);
    auto w=CreateWindowW(cls.lpszClassName,L"NetDiagnostics",WS_OVERLAPPEDWINDOW|WS_CLIPCHILDREN,
        work.left+(work.right-work.left-width)/2,work.top+(work.bottom-work.top-height)/2,width,height,nullptr,nullptr,instance,nullptr);
    if(!w)return 1;
    WINDOWPLACEMENT p{};DWORD bytes=sizeof p;
    if(RegGetValueW(HKEY_CURRENT_USER,placement_key,L"Window",RRF_RT_REG_BINARY,nullptr,&p,&bytes)==ERROR_SUCCESS &&
       bytes==sizeof p && p.length==sizeof p && MonitorFromRect(&p.rcNormalPosition,MONITOR_DEFAULTTONULL)) {
        SetWindowPlacement(w,&p);if(p.showCmd==SW_SHOWMAXIMIZED)show=SW_SHOWMAXIMIZED;
    }
    ShowWindow(w,show);UpdateWindow(w);
    MSG msg{};while(GetMessageW(&msg,nullptr,0,0)>0) {
        if(details_window && (msg.hwnd==details_window || IsChild(details_window,msg.hwnd))){
            if(msg.message==WM_KEYDOWN && msg.wParam==VK_ESCAPE){DestroyWindow(details_window);continue;}
            if(!IsDialogMessageW(details_window,&msg)){TranslateMessage(&msg);DispatchMessageW(&msg);}
            continue;
        }
        if(msg.message==WM_KEYDOWN && msg.wParam=='C' && (GetKeyState(VK_CONTROL)&0x8000) && msg.hwnd==GetDlgItem(w,list_id)){
            SendMessageW(w,WM_COMMAND,MAKEWPARAM(copy_row_id,BN_CLICKED),0);
            continue;
        }
        if(msg.message==WM_KEYDOWN && msg.wParam==VK_RETURN && msg.hwnd==GetDlgItem(w,list_id) &&
           (view.page()==9 || view.page()==10) && IsWindowVisible(GetDlgItem(w,archive_id))){
            SendMessageW(w,WM_COMMAND,MAKEWPARAM(archive_id,BN_CLICKED),reinterpret_cast<LPARAM>(GetDlgItem(w,archive_id)));
            continue;
        }
        if(!IsDialogMessageW(w,&msg)){TranslateMessage(&msg);DispatchMessageW(&msg);}
    }
    return static_cast<int>(msg.wParam);
}
