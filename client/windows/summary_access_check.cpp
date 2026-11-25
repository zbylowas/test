#include <windows.h>
#include <ole2.h>
#include <UIAutomation.h>
#include <wrl/client.h>
#include <filesystem>
#include <iostream>
#include <string>

using Microsoft::WRL::ComPtr;

namespace {
struct App {
    PROCESS_INFORMATION process{};
    HWND window{};
    ~App() {
        if(window) PostMessageW(window,WM_CLOSE,0,0);
        if(process.hProcess) {
            WaitForSingleObject(process.hProcess,10000);
            CloseHandle(process.hProcess);
            CloseHandle(process.hThread);
        }
    }
};
BOOL CALLBACK locate(HWND w,LPARAM context) {
    auto& app=*reinterpret_cast<App*>(context);
    DWORD pid{};GetWindowThreadProcessId(w,&pid);
    wchar_t name[80]{};GetClassNameW(w,name,80);
    if (pid!=app.process.dwProcessId || wcscmp(name,L"VipNetDiagnosticsWindow")!=0) return TRUE;
    app.window=w;return FALSE;
}
bool accessible(IUIAutomation* uia,HWND w,int id) {
    ComPtr<IUIAutomationElement> item;
    if(FAILED(uia->ElementFromHandle(GetDlgItem(w,id),&item)) || !item) return false;
    CONTROLTYPEID type{};BOOL focus{};BSTR name{};
    item->get_CurrentControlType(&type);item->get_CurrentIsKeyboardFocusable(&focus);item->get_CurrentName(&name);
    const bool named=name && SysStringLen(name)>0;SysFreeString(name);
    ComPtr<IUIAutomationInvokePattern> invoke;
    bool ok=SUCCEEDED(item->GetCurrentPatternAs(UIA_InvokePatternId,IID_PPV_ARGS(&invoke))) && invoke;
    if(!ok || !named || !focus || type!=UIA_ButtonControlTypeId) {
        std::cerr<<"UIA control "<<id<<", type "<<type<<", named "<<named<<", focusable "<<focus<<", invoke "<<ok<<"\n";
        return false;
    }
    return true;
}
}

int wmain(int argc,wchar_t** argv) {
    if(argc!=2 || FAILED(CoInitializeEx(nullptr,COINIT_MULTITHREADED))) return 1;
    struct Uninit {~Uninit(){CoUninitialize();}} cleanup;
    ComPtr<IUIAutomation> uia;
    if(FAILED(CoCreateInstance(__uuidof(CUIAutomation),nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&uia)))) return 1;
    App app;
    STARTUPINFOW start{};start.cb=sizeof start;start.dwFlags=STARTF_USESHOWWINDOW;start.wShowWindow=SW_SHOWNOACTIVATE;
    auto path=std::filesystem::absolute(argv[1]);std::wstring command=L"\""+path.wstring()+L"\"";
    if(!CreateProcessW(path.c_str(),command.data(),nullptr,nullptr,FALSE,0,nullptr,nullptr,&start,&app.process)) return 1;
    for(int i=0;i<300;++i) {
        EnumWindows(locate,reinterpret_cast<LPARAM>(&app));
        if(app.window && IsWindowVisible(app.window) && IsWindowEnabled(GetDlgItem(app.window,101))) break;
        Sleep(30);
    }
    if(!app.window) return 1;
    for(int id:{101,200,240,244,255,261})
        if(!accessible(uia.Get(),app.window,id)) return 1;
    std::cout<<"Native UI Automation: six named focusable buttons expose Invoke\n";
}
