#include "process_traffic.hpp"
#include <evntrace.h>
#include <evntcons.h>
#include <objbase.h>
#include <array>
#include <shellapi.h>
#include <tlhelp32.h>
#include <algorithm>
#include <atomic>
#include <cstring>
#ifdef VIPNET_TRAFFIC_TEST
#include <iostream>
#endif
#include <map>
#include <mutex>
#include <thread>

namespace traffic {
namespace {
constexpr GUID network_provider{0x7dd42a49,0x5329,0x4832,{0x8d,0xfd,0x43,0xd9,0x79,0x15,0x3a,0x88}};
constexpr unsigned max_processes=2048;
constexpr wchar_t prefix[]=L"Local\\VIP-NET-ProcessTraffic-";
using Handle=std::unique_ptr<void,decltype(&CloseHandle)>;
using Mapping=std::unique_ptr<void,decltype(&UnmapViewOfFile)>;

struct Bytes {
    DWORD pid{};
    unsigned long long received{},sent{};
};
struct Snapshot {
    unsigned long long elapsed_ms{};
    DWORD lost{}, ignored_versions{}, omitted{};
    unsigned count{};
    Bytes rows[max_processes]{};
};
struct Shared {
    volatile LONG status{}; // 0 starting, 1 ready, 2 finished, negative Win32 error
    volatile LONG sequence{};
    alignas(8) volatile LONG64 start{},end{};
    Snapshot snapshot{};
};
unsigned long long qpc() {
    LARGE_INTEGER now{};
    QueryPerformanceCounter(&now);
    return static_cast<unsigned long long>(now.QuadPart);
}
unsigned long long milliseconds(unsigned long long ticks){
    LARGE_INTEGER frequency{};
    QueryPerformanceFrequency(&frequency);
    return ticks*1000/static_cast<unsigned long long>(frequency.QuadPart);
}
unsigned long long load(volatile LONG64* value){
    return static_cast<unsigned long long>(InterlockedCompareExchange64(value,0,0));
}
bool can_collect_without_prompt(){
    alignas(void*) unsigned char sid[SECURITY_MAX_SID_SIZE]{};
    DWORD sid_size=sizeof sid;
    BOOL member=FALSE;
    if(CreateWellKnownSid(WinBuiltinPerfLoggingUsersSid,nullptr,sid,&sid_size) &&
       CheckTokenMembership(nullptr,sid,&member) && member)return true;
    HANDLE raw{};
    if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&raw))return false;
    Handle token(raw,CloseHandle);
    TOKEN_ELEVATION state{};DWORD used{};
    return GetTokenInformation(token.get(),TokenElevation,&state,sizeof state,&used) && state.TokenIsElevated;
}
std::wstring executable(){
    std::wstring path(32768,L'\0');
    auto size=GetModuleFileNameW(nullptr,path.data(),static_cast<DWORD>(path.size()));
    if(!size || size>=path.size())return {};
    path.resize(size);
    return path;
}
bool loopback(const unsigned char* address, bool ipv6){
    if(!ipv6)return address[0]==127;
    IN6_ADDR addr{};
    std::memcpy(&addr,address,16);
    return IN6_IS_ADDR_LOOPBACK(&addr) || (IN6_IS_ADDR_V4MAPPED(&addr) && address[12]==127);
}
struct Session {
    Shared& receiver;
    bool include_loopback{};
    std::mutex mutex;
    std::map<DWORD,Bytes> counts;
    DWORD invalid{},overflow{};
    std::atomic<ULONG> consume_status{ERROR_SUCCESS};

    Session(Shared& output,bool loopback):receiver(output),include_loopback(loopback){}

    static void WINAPI record(EVENT_RECORD* event) {
        if(!IsEqualGUID(event->EventHeader.ProviderId,network_provider))return;
        bool send=false,ipv6=false;
        switch(event->EventHeader.EventDescriptor.Id){
        case 26:case 58:ipv6=true;[[fallthrough]];
        case 10:case 42:send=true;break;
        case 27:case 59:ipv6=true;break;
        case 11:case 43:break;
        default:return;
        }
        auto& self=*static_cast<Session*>(event->UserContext);
        const auto stamp=static_cast<unsigned long long>(event->EventHeader.TimeStamp.QuadPart);
        const auto start=load(&self.receiver.start),end=load(&self.receiver.end);
        if(!start || stamp<start || (end && stamp>end))return;
        if(event->EventHeader.EventDescriptor.Version!=0 || event->UserDataLength<(ipv6?40:16)){
            std::lock_guard lock(self.mutex);++self.invalid;return;
        }
        const auto* data=static_cast<const unsigned char*>(event->UserData);
        if(!self.include_loopback && (loopback(data+8,ipv6) || loopback(data+(ipv6?24:12),ipv6)))return;
        DWORD pid{}, size{};
        std::memcpy(&pid,data,4);std::memcpy(&size,data+4,4);
        std::lock_guard lock(self.mutex);
        auto entry=self.counts.find(pid);
        if(entry==self.counts.end()){
            if(self.counts.size()>=max_processes){++self.overflow;return;}
            entry=self.counts.emplace(pid,Bytes{pid}).first;
        }
        if(send)entry->second.sent+=size;
        else entry->second.received+=size;
    }

    void publish(DWORD lost){
        auto start=load(&receiver.start), end=load(&receiver.end);
        if(!start)return;
        Snapshot snapshot;
        snapshot.elapsed_ms=milliseconds((end?end:qpc())-start);
        snapshot.lost=lost;
        {
            std::lock_guard lock(mutex);
            snapshot.ignored_versions=invalid; snapshot.omitted=overflow;
            for(const auto& [pid,row]:counts)snapshot.rows[snapshot.count++]=row;
        }
        InterlockedIncrement(&receiver.sequence);
        receiver.snapshot=snapshot;
        InterlockedIncrement(&receiver.sequence);
    }
};

int collect(Shared& shared,const std::wstring& guid,HANDLE stop,HANDLE parent,bool include_loopback=false) {
    struct Properties {EVENT_TRACE_PROPERTIES data{}; wchar_t name[100]{};} properties;
    auto& data=properties.data;
    auto name=L"VIP-NET-ProcessTraffic-"+guid;
    data.Wnode.BufferSize=sizeof(properties);
    data.Wnode.Flags=WNODE_FLAG_TRACED_GUID;
    data.Wnode.ClientContext=1;
    data.LogFileMode=EVENT_TRACE_REAL_TIME_MODE;
    data.LoggerNameOffset=offsetof(Properties,name);
    data.BufferSize=64;
    data.MinimumBuffers=16;
    data.MaximumBuffers=128;
    data.FlushTimer=1;
    auto fail=[&shared](ULONG error){InterlockedExchange(&shared.status,-static_cast<LONG>(error));return 1;};
    TRACEHANDLE trace{};
    auto code=StartTraceW(&trace,name.c_str(),&data);
    if(code!=ERROR_SUCCESS)return fail(code);
    code=EnableTraceEx2(trace,&network_provider,EVENT_CONTROL_CODE_ENABLE_PROVIDER,TRACE_LEVEL_VERBOSE,0x30,0,2500,nullptr);
    if(code!=ERROR_SUCCESS){
        ControlTraceW(trace,nullptr,&data,EVENT_TRACE_CONTROL_STOP);
        return fail(code);
    }
    Session session{shared,include_loopback};
    EVENT_TRACE_LOGFILEW log{};
    log.LoggerName=name.data();
    log.ProcessTraceMode=PROCESS_TRACE_MODE_REAL_TIME|PROCESS_TRACE_MODE_EVENT_RECORD|PROCESS_TRACE_MODE_RAW_TIMESTAMP;
    log.EventRecordCallback=Session::record;
    log.Context=&session;
    auto consumer=OpenTraceW(&log);
    if(consumer==INVALID_PROCESSTRACE_HANDLE){
        code=GetLastError();
        ControlTraceW(trace,nullptr,&data,EVENT_TRACE_CONTROL_STOP);
        return fail(code);
    }
    std::jthread worker([&]{session.consume_status=ProcessTrace(&consumer,1,nullptr,nullptr);});
    InterlockedExchange(&shared.status,1);
    HANDLE wait_on[]{stop,parent};
    const auto deadline=GetTickCount64()+210000;
    while(GetTickCount64()<deadline && session.consume_status==ERROR_SUCCESS){
        if(WaitForMultipleObjects(parent?2:1,wait_on,FALSE,750)!=WAIT_TIMEOUT)break;
        ControlTraceW(trace,nullptr,&data,EVENT_TRACE_CONTROL_QUERY);
        session.publish(data.EventsLost+data.RealTimeBuffersLost);
    }
    if(!load(&shared.end))InterlockedCompareExchange64(&shared.end,qpc(),0);
    const auto stopped=ControlTraceW(trace,nullptr,&data,EVENT_TRACE_CONTROL_STOP);
    if(stopped!=ERROR_SUCCESS)CloseTrace(consumer);
    worker.join();
    if(stopped==ERROR_SUCCESS)CloseTrace(consumer);
    session.publish(data.EventsLost+data.RealTimeBuffersLost);
    auto status=session.consume_status.load();
    if(status!=ERROR_SUCCESS && status!=ERROR_CANCELLED)return fail(status);
    InterlockedExchange(&shared.status,2);
    return 0;
}
std::map<DWORD,std::wstring> names(){
    std::map<DWORD,std::wstring> result;
    HANDLE raw=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if(raw==INVALID_HANDLE_VALUE)return result;
    Handle handle(raw,CloseHandle);
    PROCESSENTRY32W row{};row.dwSize=sizeof row;
    if(Process32FirstW(handle.get(),&row))do{
        result[row.th32ProcessID]=row.szExeFile;
    }while(Process32NextW(handle.get(),&row));
    return result;
}
std::wstring rate(unsigned long long bytes, unsigned long long span_ms){
    return span_ms?summary::number(bytes*0.008/span_ms)+L" Mb/s":L"—";
}
}

struct Capture::State {
    std::mutex mutex;
    Handle section{nullptr,CloseHandle}, stop{nullptr,CloseHandle}, child{nullptr,CloseHandle};
    Mapping mapping{nullptr,UnmapViewOfFile};
    std::wstring status=L"Przygotowywanie odczytu Windows…";
    Snapshot prior{};
    summary::DetailPage last_live;
    std::map<DWORD,std::wstring> label;

    Shared* shared(){return static_cast<Shared*>(mapping.get());}
};

Capture::Capture():state_(std::make_unique<State>()){}
Capture::~Capture(){finish();}
bool Capture::start(HWND owner){
    auto& s=*state_;
    GUID id{};wchar_t guid[40]{};
    if(CoCreateGuid(&id)!=S_OK || !StringFromGUID2(id,guid,40))return false;
    std::wstring key=prefix+std::wstring(guid);
    {
        std::lock_guard lock(s.mutex);
        s.section.reset(CreateFileMappingW(INVALID_HANDLE_VALUE,nullptr,PAGE_READWRITE,0,sizeof(Shared),key.c_str()));
        if(!s.section || GetLastError()==ERROR_ALREADY_EXISTS)return false;
        s.mapping.reset(MapViewOfFile(s.section.get(),FILE_MAP_WRITE,0,0,sizeof(Shared)));
        s.stop.reset(CreateEventW(nullptr,TRUE,FALSE,(key+L"-stop").c_str()));
        if(!s.mapping || !s.stop || GetLastError()==ERROR_ALREADY_EXISTS)return false;
        s.status=L"Oczekiwanie na uruchomienie licznika ruchu Windows.";
    }
    const auto initialized=CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED|COINIT_DISABLE_OLE1DDE);
    struct Uninitialize {HRESULT status; ~Uninitialize(){if(SUCCEEDED(status))CoUninitialize();}} com{initialized};
    auto args=L"--process-traffic "+std::wstring(guid)+L" "+std::to_wstring(GetCurrentProcessId());
    auto path=executable();
    if(path.empty())return false;
    SHELLEXECUTEINFOW launch{};
    launch.cbSize=sizeof launch;launch.hwnd=owner;launch.fMask=SEE_MASK_NOCLOSEPROCESS|SEE_MASK_NOASYNC;
    launch.lpVerb=can_collect_without_prompt()?L"open":L"runas";launch.lpFile=path.c_str();launch.lpParameters=args.c_str();launch.nShow=SW_HIDE;
    if(!ShellExecuteExW(&launch) || !launch.hProcess){
        const auto error=GetLastError();
        std::lock_guard lock(s.mutex);
        s.status=error==ERROR_CANCELLED?L"Anulowano zgodę Windows. Test trwa bez licznika procesów.":
            L"Nie udało się uruchomić licznika procesów · Windows "+std::to_wstring(error);
        return false;
    }
    s.child.reset(launch.hProcess);
    for(int retry=0;retry<80;++retry){
        LONG state=InterlockedCompareExchange(&s.shared()->status,0,0);
        if(state==1){
            InterlockedExchange64(&s.shared()->start,qpc());
            return true;
        }
        if(state<0 || WaitForSingleObject(s.child.get(),100)==WAIT_OBJECT_0)break;
    }
    {
        std::lock_guard lock(s.mutex);
        const auto code=InterlockedCompareExchange(&s.shared()->status,0,0);
        s.status=code<0?L"Brak odczytu ruchu procesów · Windows "+std::to_wstring(-code):
            L"Windows nie potwierdził uruchomienia licznika procesów.";
    }
    finish();
    return false;
}
void Capture::finish(){
    auto& s=*state_;
    if(!s.child)return;
    InterlockedCompareExchange64(&s.shared()->end,qpc(),0);
    SetEvent(s.stop.get());
    WaitForSingleObject(s.child.get(),3000);
    s.child.reset();
}
summary::DetailPage Capture::page(bool live,const std::wstring& phase){
    auto& state=*state_;
    std::lock_guard lock(state.mutex);
    summary::DetailPage result{state.status,{{L"Proces",216},{L"PID",71},{L"Pobiera",128},{L"Wysyła",128},{L"Ruch od startu",165}},{}};
    auto* shared=state.shared();
    if(!shared)return result;
    const auto status=InterlockedCompareExchange(&shared->status,0,0);
    Snapshot current;
    for(int try_read=0;try_read<4;++try_read){
        auto version=InterlockedCompareExchange(&shared->sequence,0,0);
        if(version%2)continue;
        current=shared->snapshot;
        if(version==InterlockedCompareExchange(&shared->sequence,0,0))break;
        current={};
    }
    if(status<0){result.subtitle=L"Brak danych ETW · kod Windows "+std::to_wstring(-status);return result;}
    if(!current.elapsed_ms)return result;
    result.subtitle=(live?phase+L" · Ruch TCP i UDP według procesu":L"Średni ruch procesów podczas ostatniego testu");
    if(current.lost || current.omitted || current.ignored_versions)
        result.subtitle+=L" · Dane częściowe";
    bool interval=live && state.prior.elapsed_ms<current.elapsed_ms;
    if(live && !interval && !state.last_live.rows.empty()){
        result.rows=state.last_live.rows;
        return result;
    }
    auto span=interval?current.elapsed_ms-state.prior.elapsed_ms:current.elapsed_ms;
    auto known=names();
    for(auto& [pid,name]:known)state.label.try_emplace(pid,std::move(name));
    std::map<DWORD,Bytes> previous;
    if(interval)for(unsigned i=0;i<state.prior.count && i<max_processes;++i)
        previous.emplace(state.prior.rows[i].pid,state.prior.rows[i]);
    struct Row { Bytes overall; unsigned long long rx,tx; };
    std::vector<Row> rows;
    unsigned long long other_rx=0,other_tx=0;
    for(unsigned i=0;i<current.count && i<max_processes;++i){
        auto row=current.rows[i],before=previous[row.pid];
        rows.push_back({row,row.received>=before.received?row.received-before.received:0,
                            row.sent>=before.sent?row.sent-before.sent:0});
        if(row.pid && row.pid!=GetCurrentProcessId()){
            other_rx+=rows.back().rx;
            other_tx+=rows.back().tx;
        }
    }
    if(live && interval)state.prior=current;
    result.subtitle+=L" · Inne procesy ↓ "+rate(other_rx,span)+L" / ↑ "+rate(other_tx,span);
    std::stable_sort(rows.begin(),rows.end(),[](const Row& a,const Row& b){return a.rx+a.tx>b.rx+b.tx;});
    if(rows.empty()){
        result.rows.push_back({{L"Brak zdarzeń TCP/UDP"},L"W tym oknie Windows nie zarejestrował ruchu poza loopback.",{},{}});
        return result;
    }
    for(const auto& row:rows){
        auto pid=row.overall.pid;
        auto entry=state.label.find(pid);
        auto name=pid==GetCurrentProcessId()?L"VIP-NET · aplikacja testowa":
            entry!=state.label.end()?entry->second:pid?L"Proces zakończony / nazwa niedostępna":L"Windows · brak przypisania PID";
        result.rows.push_back({{name,std::to_wstring(pid),rate(row.rx,span),rate(row.tx,span),
            summary::number((row.overall.received+row.overall.sent)/1000000.)+L" MB"},
            L"Zdarzenia warstwy TCP/UDP Windows dla tego PID. Ruch obejmuje karty w komputerze, również sieć lokalną. Loopback jest pomijany. "
            L"Ostatni pełny wynik podaje średnią z czasu odczytu. Rozmiary zdarzeń mogą różnić się od danych aplikacyjnych i licznika karty.",{},{}});
    }
    if(live)state.last_live=result;
    return result;
}

int run_helper(std::wstring_view arguments){
    if(arguments.size()<40 || arguments.size()>49 || arguments[38]!=L' ')return 2;
    GUID parsed{};
    std::wstring guid(arguments.substr(0,38)),pid_text(arguments.substr(39));
    if(CLSIDFromString(guid.c_str(),&parsed)!=S_OK || pid_text.find_first_not_of(L"0123456789")!=pid_text.npos)return 2;
    auto pid=wcstoul(pid_text.c_str(),nullptr,10);
    if(!pid)return 2;
    Handle parent(OpenProcess(SYNCHRONIZE,FALSE,pid),CloseHandle);
    auto key=prefix+guid;
    Handle section(OpenFileMappingW(FILE_MAP_WRITE,FALSE,key.c_str()),CloseHandle);
    Handle stop(OpenEventW(SYNCHRONIZE,FALSE,(key+L"-stop").c_str()),CloseHandle);
    if(!section || !stop || !parent)return 2;
    Mapping view(MapViewOfFile(section.get(),FILE_MAP_WRITE,0,0,sizeof(Shared)),UnmapViewOfFile);
    if(!view)return 2;
    return collect(*static_cast<Shared*>(view.get()),guid,stop.get(),parent.get());
}
#ifdef VIPNET_TRAFFIC_TEST
int verify_loopback(){
    Shared synthetic{};
    InterlockedExchange64(&synthetic.start,100);
    Session parser{synthetic,false};
    EVENT_RECORD fixture{};
    fixture.UserContext=&parser;
    fixture.EventHeader.ProviderId=network_provider;
    fixture.EventHeader.TimeStamp.QuadPart=101;
    DWORD payload[10]{345,1500,0,0};
    auto* raw=reinterpret_cast<unsigned char*>(payload);
    raw[8]=192;raw[9]=0;raw[10]=2;raw[11]=1;
    raw[12]=198;raw[13]=51;raw[14]=100;raw[15]=2;
    fixture.UserData=payload;fixture.UserDataLength=sizeof payload;
    fixture.EventHeader.EventDescriptor.Id=10;Session::record(&fixture);
    fixture.EventHeader.EventDescriptor.Id=43;Session::record(&fixture);
    raw[12]=127;Session::record(&fixture);raw[12]=198;
    fixture.EventHeader.EventDescriptor.Version=255;Session::record(&fixture);
    auto& counts=parser.counts.at(345);
    if(counts.sent!=1500 || counts.received!=1500 || parser.invalid!=1)return 1;
    fixture.EventHeader.EventDescriptor.Version=0;
    fixture.EventHeader.EventDescriptor.Id=26;
    std::memset(raw+8,0,32);
    raw[8]=0x20;raw[9]=1;raw[10]=0x0d;raw[11]=0xb8;
    raw[24]=0x20;raw[25]=1;raw[26]=0x0d;raw[27]=0xb8;
    Session::record(&fixture);
    if(counts.sent!=3000)return 1;

    Shared real{};
    Handle stop(CreateEventW(nullptr,TRUE,FALSE,nullptr),CloseHandle);
    GUID id{};wchar_t guid[40]{};
    if(!stop || CoCreateGuid(&id)!=S_OK || !StringFromGUID2(id,guid,40))return 1;
    struct Stop {HANDLE event;~Stop(){SetEvent(event);}}; // Stop runs before the thread joins.
    std::jthread runner([&]{collect(real,guid,stop.get(),nullptr,true);});
    Stop guard{stop.get()};
    for(int i=0;i<60 && !InterlockedCompareExchange(&real.status,0,0);++i)Sleep(100);
    auto status=InterlockedCompareExchange(&real.status,0,0);
    if(status==-ERROR_ACCESS_DENIED){
        std::cout<<"ETW access denied; synthetic IPv4/IPv6 and loopback exclusion passed.\n";
        return 77;
    }
    if(status!=1){std::cout<<"ETW start status "<<status<<"\n";return 1;}
    WSADATA ws{};
    if(WSAStartup(MAKEWORD(2,2),&ws))return 1;
    struct Wsa {~Wsa(){WSACleanup();}} wsa;
    InterlockedExchange64(&real.start,qpc());
    unsigned sent_bytes=0;
    for(int family:{AF_INET,AF_INET6}){
        auto receiver=socket(family,SOCK_DGRAM,IPPROTO_UDP);
        auto sender=socket(family,SOCK_DGRAM,IPPROTO_UDP);
        struct SocketPair {SOCKET a,b;~SocketPair(){closesocket(a);closesocket(b);}} pair{receiver,sender};
        if(receiver==INVALID_SOCKET || sender==INVALID_SOCKET)return 1;
        SOCKADDR_INET local{};
        local.si_family=static_cast<ADDRESS_FAMILY>(family);
        if(family==AF_INET)local.Ipv4.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
        else local.Ipv6.sin6_addr=in6addr_loopback;
        int length=family==AF_INET?sizeof(SOCKADDR_IN):sizeof(SOCKADDR_IN6);
        DWORD timeout=2000;
        setsockopt(receiver,SOL_SOCKET,SO_RCVTIMEO,reinterpret_cast<const char*>(&timeout),sizeof timeout);
        auto addr=reinterpret_cast<SOCKADDR*>(&local);
        if(bind(receiver,addr,length) || getsockname(receiver,addr,&length))return 1;
        std::array<char,768> sample{};
        for(int i=0;i<100;++i){
            int n=static_cast<int>(sample.size());
            if(sendto(sender,sample.data(),n,0,addr,length)!=n ||
               recv(receiver,sample.data(),n,0)!=n)return 1;
            sent_bytes+=n;
        }
    }
    InterlockedExchange64(&real.end,qpc());
    SetEvent(stop.get());
    runner.join();
    auto pid=GetCurrentProcessId();
    auto first=real.snapshot.rows,last=first+real.snapshot.count;
    auto match=std::find_if(first,last,[pid](const Bytes& row){return row.pid==pid;});
    if(real.status!=2 || real.snapshot.lost || match==last){
        std::cout<<"ETW terminal status "<<real.status<<", reported processes "<<real.snapshot.count<<"\n";
        return 1;
    }
    std::cout<<"Loopback ETW counted received "<<match->received<<" and sent "<<match->sent
             <<" bytes for the test process, payload "<<sent_bytes<<"\n";
    return match->received>=sent_bytes && match->sent>=sent_bytes?0:1;
}
#endif

}
