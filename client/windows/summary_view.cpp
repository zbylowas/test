#include "summary_view.hpp"
#include "desktop_brand.hpp"
#include <algorithm>
#include <cmath>
#include <filesystem>
#include <windowsx.h>

namespace summary {
namespace {
constexpr COLORREF bg=RGB(243,243,243),surface=RGB(255,255,255),ink=RGB(32,32,32),muted=RGB(97,97,97),
    border=RGB(224,224,224),accent=RGB(0,103,192),green=RGB(16,124,16),amber=RGB(157,93,0),red=RGB(196,43,28);
constexpr std::array<const wchar_t*,12> sections{L"Podsumowanie",L"Prędkość internetu",L"Komputer",L"Sieć lokalna",L"Wi-Fi",L"Internet",L"Gry online",L"MTR i Traceroute",L"Monitoring",L"Historia",L"Raporty",L"Ustawienia"};
constexpr std::array<wchar_t,12> nav_icons{0xe80f,0xe945,0xe7f8,0xe968,0xe701,0xe774,0xe7fc,0xe8ab,0xe9d9,0xe81c,0xe8a5,0xe713};
constexpr std::array<wchar_t,10> check_icons{0xe7f8,0xe701,0xe968,0xe839,0xe774,0xe12b,0xe968,0xe968,0xe9d9,0xe916};
constexpr std::array<const wchar_t*,7> units{L"Mb/s",L"Mb/s",L"ms",L"ms",L"%",L"ms",L"ms"};
COLORREF tone_color(Tone t) {
    if (t==Tone::warning) return amber;
    if (t==Tone::problem) return red;
    return t==Tone::observed?green:muted;
}
void fill(HDC dc,RECT r,COLORREF color) {
    SetDCBrushColor(dc,color);FillRect(dc,&r,static_cast<HBRUSH>(GetStockObject(DC_BRUSH)));
}
void box(HDC dc,RECT r,COLORREF color,COLORREF stroke,int rad) {
    SelectObject(dc,GetStockObject(DC_BRUSH)); SetDCBrushColor(dc,color);
    SelectObject(dc,GetStockObject(DC_PEN)); SetDCPenColor(dc,stroke);
    RoundRect(dc,r.left,r.top,r.right,r.bottom,rad,rad);
}
std::wstring window_text(HWND w) {
    std::wstring s(GetWindowTextLengthW(w)+1,L'\0');
    s.resize(GetWindowTextW(w,s.data(),static_cast<int>(s.size()))); return s;
}
void set(HWND w,const std::wstring& value) {
    if (window_text(w)!=value) SetWindowTextW(w,value.c_str());
}
void write(HDC dc,HFONT font,COLORREF color,RECT r,std::wstring_view s,UINT align=DT_LEFT) {
    SelectObject(dc,font);SetTextColor(dc,color);SetBkMode(dc,TRANSPARENT);
    DrawTextW(dc,s.data(),static_cast<int>(s.size()),&r,DT_NOPREFIX|DT_SINGLELINE|DT_VCENTER|DT_END_ELLIPSIS|align);
}
void line(HDC dc,int x1,int y1,int x2,int y2,COLORREF c) {
    SelectObject(dc,GetStockObject(DC_PEN));SetDCPenColor(dc,c);
    MoveToEx(dc,x1,y1,nullptr);LineTo(dc,x2,y2);
}
LRESULT CALLBACK hover_card(HWND w,UINT msg,WPARAM a,LPARAM b,UINT_PTR id,DWORD_PTR owner) {
    if (msg==WM_MOUSEMOVE) reinterpret_cast<View*>(owner)->hover(w,GET_X_LPARAM(b));
    if (msg==WM_NCDESTROY) RemoveWindowSubclass(w,hover_card,id);
    return DefSubclassProc(w,msg,a,b);
}
int CALLBACK font_found(const LOGFONTW*,const TEXTMETRICW*,DWORD,LPARAM found) {
    *reinterpret_cast<bool*>(found)=true;return 0;
}
}
int View::px(int v) const {return MulDiv(v,dpi_,96);}
HWND View::child(const wchar_t* type,const wchar_t* caption,DWORD style,int id) {
    return CreateWindowExW(0,type,caption,WS_CHILD|style,0,0,1,1,parent_,reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),GetModuleHandleW(nullptr),nullptr);
}
HWND View::button(const wchar_t* name,int id) {return child(L"BUTTON",name,BS_OWNERDRAW|WS_TABSTOP,id);}
HWND View::label(const wchar_t* name) {return child(L"STATIC",name,SS_CENTERIMAGE|SS_ENDELLIPSIS|SS_NOPREFIX,0);}
void View::hint(HWND w,const std::wstring& caption) {
    // The common control copies literals passed with TTM_SETTOOLINFO, but a stable backing string also supports older Windows.
    auto& text=tips_[w];
    if (text==caption) return;
    text=caption;
    TOOLINFOW tool{sizeof tool};tool.uFlags=TTF_IDISHWND|TTF_SUBCLASS;tool.hwnd=parent_;
    tool.uId=reinterpret_cast<UINT_PTR>(w);tool.lpszText=text.data();
    if (!SendMessageW(tools_,TTM_ADDTOOLW,0,reinterpret_cast<LPARAM>(&tool)))
        SendMessageW(tools_,TTM_UPDATETIPTEXTW,0,reinterpret_cast<LPARAM>(&tool));
}
void View::create(HWND parent,std::wstring origin,std::wstring brand) {
    parent_=parent;origin_=std::move(origin);brand_name_=std::move(brand);
    tools_=CreateWindowExW(WS_EX_TOPMOST,TOOLTIPS_CLASSW,nullptr,WS_POPUP|TTS_ALWAYSTIP|TTS_NOPREFIX,
                           0,0,0,0,parent,nullptr,GetModuleHandleW(nullptr),nullptr);
    SendMessageW(tools_,TTM_SETMAXTIPWIDTH,0,440);
    menu_=button(L"Zwiń lub rozwiń nawigację",menu_id);
    brand_=child(L"STATIC",brand_name_.c_str(),SS_OWNERDRAW,110);
    for (size_t i=0;i<nav_.size();++i) {
        nav_[i]=button(sections[i],nav_id+static_cast<int>(i));
        hint(nav_[i],sections[i]);

    }
    std::array<wchar_t,32768> exe{};
    if (GetModuleFileNameW(nullptr,exe.data(),static_cast<DWORD>(exe.size()))) {
        auto logo=std::filesystem::path(exe.data()).parent_path()/L"operator.ico";
        logo_=static_cast<HICON>(LoadImageW(nullptr,logo.c_str(),IMAGE_ICON,0,0,LR_LOADFROMFILE|LR_DEFAULTSIZE));
    }
    title_=label(L"Podsumowanie");sub_=label(L"Gotowy do pomiaru");time_=child(L"STATIC",L"",SS_RIGHT|SS_CENTERIMAGE|SS_NOPREFIX,0);
    measurement_=label(L"Wynik pomiaru");diagnostics_=label(L"Stan diagnostyki");
    profile_label_=label(L"Profil pomiaru");
    profile_=child(L"COMBOBOX",L"Profil pomiaru",WS_TABSTOP|CBS_DROPDOWNLIST|WS_VSCROLL,profile_id);
    for (auto s:{L"Pełna prędkość",L"Mały transfer"}) SendMessageW(profile_,CB_ADDSTRING,0,reinterpret_cast<LPARAM>(s));
    SendMessageW(profile_,CB_SETCURSEL,0,0);
    hint(profile_,L"Pełna prędkość używa profilu przepustowości serwera. Mały transfer mierzy mniejszą, ustaloną porcję danych.");
    start_=button(L"Rozpocznij test",start_id);stop_=button(L"Zatrzymaj test",stop_id);
    report_=button(L"Pełny raport",report_id);copy_=button(L"Kopiuj kod do panelu",copy_id);
    back_=button(L"Podsumowanie",back_id);
    for (size_t i=0;i<metrics_.size();++i) metrics_[i]=button(L"",metric_id+static_cast<int>(i));
    for (size_t i=0;i<2;++i) SetWindowSubclass(metrics_[i],hover_card,1,reinterpret_cast<DWORD_PTR>(this));
    for (size_t i=0;i<checks_.size();++i) checks_[i]=button(L"",check_id+static_cast<int>(i));
    finding_=button(L"",finding_id);footer_=child(L"STATIC",L"",SS_OWNERDRAW,111);
    detail_=child(L"EDIT",L"",WS_TABSTOP|ES_MULTILINE|ES_READONLY|WS_VSCROLL|ES_AUTOVSCROLL,112);
    for(int i=0;i<3;++i)facts_[i]=child(L"STATIC",L"",SS_OWNERDRAW,320+i);
    table_=child(WC_LISTVIEWW,L"Wyniki diagnostyczne",LVS_REPORT|LVS_SINGLESEL|LVS_SHOWSELALWAYS|WS_TABSTOP,list_id);
    ListView_SetExtendedListViewStyle(table_,LVS_EX_FULLROWSELECT|LVS_EX_DOUBLEBUFFER|LVS_EX_LABELTIP);
    graph_=child(L"STATIC",L"Szczegóły wyniku",SS_OWNERDRAW,graph_id);
    target_=child(L"EDIT",L"",WS_BORDER|ES_AUTOHSCROLL|WS_TABSTOP,target_id);
    SendMessageW(target_,EM_SETLIMITTEXT,253,0);
    SendMessageW(target_,EM_SETCUEBANNER,TRUE,reinterpret_cast<LPARAM>(L"Adres IP lub nazwa DNS"));
    auto combo=[&](int id,const wchar_t* name){return child(L"COMBOBOX",name,WS_TABSTOP|CBS_DROPDOWNLIST|WS_VSCROLL,id);};
    choice_=combo(choice_id,L"Profil lub liczba prób");mode_=combo(mode_id,L"Metoda");region_=combo(region_id,L"Serwer lub usługa gry");
    SendMessageW(region_,CB_SETDROPPEDWIDTH,360,0);
    limit_=combo(limit_id,L"Maksymalna liczba skoków");interval_=combo(interval_id,L"Odstęp między próbami");
    game_method_=combo(game_method_id,L"Rodzaj testu gry");game_length_=combo(game_length_id,L"Długość testu gry");
    choices(game_method_id,{L"Ping do celu",L"Trasa MTR"});choices(game_length_id,{L"20 przebiegów",L"100 przebiegów",L"300 przebiegów"});
    family_=combo(family_id,L"Rodzina adresów IP");choices(family_id,{L"Auto IP",L"IPv4",L"IPv6"});
    favorite_=button(L"Zapisz cel",favorite_id);saved_=combo(saved_id,L"Ulubione cele");
    choices(limit_id,{L"8 skoków",L"16 skoków",L"32 skoki"},1);
    choices(interval_id,{L"100 ms",L"500 ms",L"1000 ms"},0);
    update_=button(L"Sprawdź aktualizacje",update_id);
    archive_=button(L"Otwórz raport",archive_id);compare_=button(L"Porównaj trasę",compare_id);action_=button(L"Wykonaj test",action_id);export_=button(L"Eksportuj…",export_id);
    copy_row_=button(L"Kopiuj wiersz",copy_row_id);refresh_live_=button(L"Odśwież odczyt",refresh_live_id);
    scale(GetDpiForWindow(parent)); update(read(nullptr));
}
void View::scale(UINT dpi) {
    dpi_=dpi?dpi:96;
    LOGFONTW family{};family.lfCharSet=DEFAULT_CHARSET;wcscpy_s(family.lfFaceName,L"Segoe UI Variable Text");
    bool found=false;auto dc=GetDC(parent_);
    EnumFontFamiliesExW(dc,&family,font_found,reinterpret_cast<LPARAM>(&found),0);ReleaseDC(parent_,dc);
    const int sizes[]={13,14,19,28,34,12,17,15};
    for (int i=0;i<8;++i) {
        auto old=fonts_[i];
        fonts_[i]=CreateFontW(-px(sizes[i]),0,0,0,(i==2||i==3||i==4)?FW_SEMIBOLD:FW_NORMAL,0,0,0,
            DEFAULT_CHARSET,0,0,CLEARTYPE_QUALITY,0,i==6?L"Segoe MDL2 Assets":found?L"Segoe UI Variable Text":L"Segoe UI");
        if (old) DeleteObject(old);
    }
    for (auto w:{sub_,time_,footer_,profile_label_}) SendMessageW(w,WM_SETFONT,reinterpret_cast<WPARAM>(fonts_[0]),FALSE);
    for (auto w:{profile_,detail_,table_,target_,choice_,mode_,region_,limit_,interval_,family_,saved_,game_method_,game_length_}) SendMessageW(w,WM_SETFONT,reinterpret_cast<WPARAM>(fonts_[1]),FALSE);
    for (auto w:{measurement_,diagnostics_}) SendMessageW(w,WM_SETFONT,reinterpret_cast<WPARAM>(fonts_[2]),FALSE);
    for(size_t i=0;i<table_data_.columns.size();++i)ListView_SetColumnWidth(table_,static_cast<int>(i),px(table_data_.columns[i].second));
    SendMessageW(title_,WM_SETFONT,reinterpret_cast<WPARAM>(fonts_[3]),FALSE);
    layout();
}
void View::move(HWND w,int x,int y,int width,int height,bool show) {
    if (show) { MoveWindow(w,px(x),px(y-(w==footer_?0:offset_)),px(std::max(1,width)),px(std::max(1,height)),TRUE);ShowWindow(w,SW_SHOWNA); }
    else ShowWindow(w,SW_HIDE);
}
void View::layout() {
    if (!footer_) return;
    RECT r{};GetClientRect(parent_,&r);
    int width=MulDiv(r.right,96,dpi_),height=MulDiv(r.bottom,96,dpi_);
    const int viewport=height;
    height=std::max(590,height);
    scroll_limit_=height-viewport;
    offset_=std::clamp(offset_,0,scroll_limit_);
    SCROLLINFO si{sizeof si,SIF_RANGE|SIF_PAGE|SIF_POS};
    si.nMax=height-1;si.nPage=viewport;si.nPos=offset_;
    SetScrollInfo(parent_,SB_VERT,&si,TRUE);
    bool small=height<700;
    compact_=collapsed_ || width<940;
    int rail=compact_?60:width<1080?174:208;
    int pad=width<1080?16:26,x=rail+pad,area=width-x-pad;
    int bar=30, nav_top=small?72:88,rowh=std::clamp((height-bar-nav_top-12)/13,31,42);
    move(brand_,8,10,rail-16,44,!compact_);move(menu_,compact_?8:rail-42,compact_?14:58,38,28);
    for (int i=0;i<12;++i) move(nav_[i],8,nav_top+i*rowh+(i>=9?7:0),rail-16,rowh-2);
    bool home_page=page_==0;
    move(title_,x,small?10:18,area-350,40);
    move(sub_,x,small?49:61,home_page?area-345:area-8,24);
    move(profile_label_,x+area-313,small?8:16,140,20,home_page);
    move(profile_,x+area-313,small?30:39,145,140,home_page);
    move(start_,x+area-152,small?24:33,152,36,home_page && !busy_);
    move(stop_,x+area-152,small?24:33,152,36,home_page && busy_);
    move(back_,x+area-135,24,135,34,!home_page);
    int y=small?77:100;
    move(measurement_,x,y,area/2,28,home_page);
    move(time_,x+area/2,y,area/2,28,home_page);
    y+=34;
    int chart_height=std::clamp((height-405)/2,100,182), gap=8,half=(area-gap)/2;
    move(metrics_[0],x,y,half,chart_height,home_page);move(metrics_[1],x+half+gap,y,area-half-gap,chart_height,home_page);
    y+=chart_height+gap;
    int strip=small?60:74;
    for (int i=0;i<5;++i) {
        int a=area*i/5,b=area*(i+1)/5;
        move(metrics_[i+2],x+a,y,b-a-(i==4?0:gap),strip,home_page);
    }
    y+=strip+(small?10:18);
    move(diagnostics_,x,y,area/2,30,home_page);
    const bool narrow_actions=(page_==7 || page_==9 || page_==10) && area<728;
    move(report_,home_page?x+area-130:x+(narrow_actions?152:190),home_page?y:height-bar-46,narrow_actions?118:130,home_page?30:32);
    y+=34;
    int status_h=std::clamp((height-bar-y-(small?43:60))/5,26,52);
    for (int i=0;i<10;++i) {
        int col=i%2;
        move(checks_[i],x+col*(half+gap),y+(i/2)*status_h,col?area-half-gap:half,status_h-2,home_page);
    }
    y+=5*status_h+4;
    move(finding_,x,y,area,std::clamp(height-bar-y-4,24,44),home_page);
    bool route=workspace_ && page_>=6 && page_<=8;
    bool games=route && page_==6, mtr=route && page_==7;
    int top=small?83:100,footer_y=height-bar-46;
    move(detail_,x,top,area,footer_y-top-8,!home_page && !workspace_);
    int input=std::max(155,area-426);
    move(target_,x,games?top+39:top,games?area-303:input,30,route);
    move(choice_,games?x:x+input+8,top,games?180:150,300,route);
    move(mode_,x+input+166,top,110,160,route && !games);
    move(region_,x+188,top,area-338,220,games);
    move(action_,x+area-142,top,142,31,route);
    move(limit_,x,top+39,130,150,mtr);
    move(interval_,x+138,top+39,115,150,mtr);
    move(family_,x+261,top+39,92,120,mtr);
    move(favorite_,x+361,top+39,105,28,mtr);
    move(saved_,x+474,top+39,area-474,230,mtr);
    move(game_method_,x+area-295,top+39,135,130,games);move(game_length_,x+area-152,top+39,152,150,games);
    if(route)top+=mtr || games?82:45;
    int panel_h=small?94:116;
    bool cards=workspace_ && !table_data_.rows.empty() && (page_<=5 || page_==6 || page_==8);
    for(int i=0;i<3;++i){
        int left=area*i/3,right=area*(i+1)/3;
        move(facts_[i],x+left,top,right-left-6,small?51:65,cards && static_cast<size_t>(i)<table_data_.rows.size());
    }
    if(cards)top+=small?58:74;
    move(table_,x,top,area,footer_y-top-panel_h-14,workspace_);
    move(graph_,x,footer_y-panel_h-6,area,panel_h,workspace_);
    move(update_,x+area-327,24,184,34,workspace_ && page_==11);
    move(archive_,x+area-264,footer_y,132,32,workspace_ && (page_==9 || page_==10));
    EnableWindow(archive_,!busy_ && !table_data_.rows.empty());
    move(compare_,x+area-264,footer_y,132,32,mtr && !busy_);
    move(export_,x+area-124,footer_y,124,32,workspace_);
    const bool action_right=mtr || page_==9 || page_==10;
    move(copy_row_,x+area-(action_right?398:258),footer_y,126,32,workspace_);
    move(refresh_live_,x+area-290,24,142,34,workspace_ && (page_==2 || page_==3));
    move(copy_,x,height-bar-46,narrow_actions?142:180,32,!home_page);
    move(footer_,0,viewport-bar,width,bar);
    SetWindowPos(footer_,HWND_TOP,0,0,0,0,SWP_NOMOVE|SWP_NOSIZE|SWP_NOACTIVATE);
    InvalidateRect(parent_,nullptr,TRUE);
}
void View::controls(bool busy,bool has_code,bool has_details) {
    bool changed=busy_!=busy;busy_=busy;
    EnableWindow(start_,!busy);EnableWindow(profile_,!busy);EnableWindow(copy_,!busy && has_code);
    EnableWindow(report_,has_details && !busy);
    if (changed) layout();
}
bool View::capacity() const {return SendMessageW(profile_,CB_GETCURSEL,0,0)==0;}
void View::phase(const std::wstring& label) {operation_=label;refresh_labels();}
void View::update(const Snapshot& s) {data_=s;refresh_labels();}
void View::refresh_labels() {
    set(sub_,workspace_?table_data_.subtitle:page_?L"Szczegóły diagnostyczne":operation_.empty()?(data_.recorded?(data_.partial?L"Pomiar częściowy":L"Pomiar zakończony"):L"Gotowy do pomiaru"):operation_);
    set(time_,data_.recorded?L"Ostatni test   "+data_.last:data_.last);
    for (size_t i=0;i<metrics_.size();++i) {
        auto& f=data_.metrics[i];
        auto caption=f.label+L"   "+f.value+(f.value==L"—"?L"":L" "+std::wstring(units[i]));
        set(metrics_[i],caption);
        auto tip=f.detail;
        if (i<2 && !data_.lines[i].empty()) {
            const auto& line=data_.lines[i];
            double peak=0;for (auto p:line) peak=std::max(peak,p.mbps);
            tip+=L" Ostatnia próbka: "+number(line.back().mbps)+L" Mb/s. Maksimum próbek: "+number(peak)+L" Mb/s.";
        }
        hint(metrics_[i],tip);
    }
    for (size_t i=0;i<checks_.size();++i) {
        auto& f=data_.checks[i];set(checks_[i],f.label+L"   "+f.value);hint(checks_[i],f.detail);
    }
    set(finding_,data_.finding+(data_.action.empty()?L"":L" "+data_.action));hint(finding_,data_.finding_detail);
    std::wstring server=busy_?L"Pomiar w toku":data_.synced?L"Serwer potwierdził zapis":L"Brak potwierdzenia serwera";
    auto context=report_status_.empty()?server+L"   ·   "+data_.save_status:report_status_;
    set(footer_,context+L"   ·   "+(busy_?L"Pomiar w toku":operation_.empty()?L"Gotowy":operation_)+L"   |   "+origin_+L"   ·   "+desktop_version);
    InvalidateRect(footer_,nullptr,FALSE);
}
void View::live(size_t dir,const Json& counters) {
    auto points=rates(counters);if (points.empty() || (data_.lines[dir].size()==points.size() && !data_.lines[dir].empty())) return;
    data_.lines[dir]=std::move(points);
    auto& f=data_.metrics[dir];f.value=number(data_.lines[dir].back().mbps);
    f.detail=L"Chwilowy transfer aplikacji, obliczony z przyrostu licznika bajtów i czasu między odczytami.";
    refresh_labels();InvalidateRect(metrics_[dir],nullptr,FALSE);
}
void View::scroll(int command) {
    if (!scroll_limit_) return;
    int next=offset_;
    SCROLLINFO si{sizeof si,SIF_TRACKPOS|SIF_PAGE};
    GetScrollInfo(parent_,SB_VERT,&si);
    if(command==SB_LINEUP) next-=36;
    if(command==SB_LINEDOWN) next+=36;
    if(command==SB_PAGEUP) next-=static_cast<int>(si.nPage);
    if(command==SB_PAGEDOWN) next+=static_cast<int>(si.nPage);
    if(command==SB_THUMBTRACK || command==SB_THUMBPOSITION) next=si.nTrackPos;
    next=std::clamp(next,0,scroll_limit_);
    if (offset_!=next) {offset_=next;layout();}
}
void View::toggle_rail() {collapsed_=!collapsed_;layout();}
void View::details(int nav,const std::wstring& caption,const std::wstring& content) {
    workspace_=false;page_=nav?nav:10;set(title_,caption);set(detail_,content);
    SendMessageW(detail_,EM_SETSEL,0,0);SendMessageW(detail_,EM_SCROLLCARET,0,0);
    refresh_labels();layout();SetFocus(back_);
}
void View::home() {report_status_.clear();workspace_=false;page_=0;set(title_,sections[0]);refresh_labels();layout();SetFocus(nav_[0]);}
void View::background(HDC dc) {
    RECT r{};GetClientRect(parent_,&r);fill(dc,r,bg);
    int width=MulDiv(r.right,96,dpi_),rail=compact_?60:width<1080?174:208;
    line(dc,px(rail),0,px(rail),r.bottom,border);
}
bool View::draw(const DRAWITEMSTRUCT& item) {
    int id=static_cast<int>(item.CtlID),ww=item.rcItem.right,hh=item.rcItem.bottom;
    if (ww<=0 || hh<=0) return true;
    auto dc=CreateCompatibleDC(item.hDC);auto bmp=CreateCompatibleBitmap(item.hDC,ww,hh);
    if (!dc || !bmp) {if(dc)DeleteDC(dc);if(bmp)DeleteObject(bmp);return false;}
    auto old=SelectObject(dc,bmp);
    RECT all{0,0,ww,hh};fill(dc,all,bg);
    int w=MulDiv(ww,96,dpi_),h=MulDiv(hh,96,dpi_);
    auto rect=[&](int x,int y,int r,int b)->RECT{return {px(x),px(y),px(r),px(b)};};
    auto text=[&](int f,COLORREF c,int x,int y,int r,int b,std::wstring_view t,UINT align=DT_LEFT) {
        write(dc,fonts_[f],c,rect(x,y,r,b),t,align);
    };
    auto glyph=[&](wchar_t icon,COLORREF color,int x,int y,int width,int height) {
        text(6,color,x,y,x+width,y+height,std::wstring_view(&icon,1),DT_CENTER);
    };
    bool disabled=item.itemState&ODS_DISABLED,pressed=item.itemState&ODS_SELECTED;
    auto panel=[&](COLORREF face=surface,COLORREF outline=border) {box(dc,all,face,outline,px(9));};
    if(id>=320 && id<=322){
        panel();size_t index=id-320;
        if(index<table_data_.rows.size() && table_data_.rows[index].cells.size()>=2){
            auto& cells=table_data_.rows[index].cells;
            text(0,muted,12,3,w-12,h/2,cells[0]);
            text(2,ink,12,h/2-2,w-12,h-3,cells[1]);
        }
    }else if (id==graph_id) {
        panel();int index=selected();
        if(index>=0 && static_cast<size_t>(index)<table_data_.rows.size()) {
            auto& row=table_data_.rows[index];
            auto d=rect(14,6,w-14,row.points.empty()?h-5:41);SelectObject(dc,fonts_[1]);SetBkMode(dc,TRANSPARENT);SetTextColor(dc,ink);
            DrawTextW(dc,row.detail.c_str(),-1,&d,DT_WORDBREAK|DT_END_ELLIPSIS|DT_NOPREFIX);
            if (!row.points.empty()){
                double peak=1;for(auto point:row.points)if(point)peak=std::max(peak,*point);
                text(5,muted,12,44,76,66,number(peak)+L" "+row.unit);
                text(5,muted,12,h-26,72,h-6,L"0 "+row.unit);
                line(dc,px(78),px(h-12),px(w-14),px(h-12),border);
                bool prev=false;int lx=0,ly=0;
                for(size_t i=0;i<row.points.size();++i){
                    if(!row.points[i]){prev=false;continue;}
                    int cx=px(80+int((w-100)*double(i)/std::max<size_t>(1,row.points.size()-1)));
                    int cy=px(h-13-int((h-60)*(*row.points[i])/peak));
                    if(prev)line(dc,lx,ly,cx,cy,accent);
                    fill(dc,{cx-1,cy-1,cx+2,cy+2},accent);lx=cx;ly=cy;prev=true;
                }
            }
        }else text(1,muted,16,0,w-16,h,L"Brak zebranych wyników.");
    } else if (id==110) {
        if (logo_) DrawIconEx(dc,px(7),px(7),logo_,px(30),px(30),0,nullptr,DI_NORMAL);
        else {
            box(dc,rect(7,7,37,37),accent,accent,px(8));
            glyph(0xe9d9,surface,7,7,30,30);
        }
        text(2,ink,45,0,w,44,brand_name_);
    } else if (id==111) {
        line(dc,0,0,ww,0,border);text(5,muted,16,1,w-12,h,window_text(item.hwndItem));
    } else if (id>=nav_id && id<nav_id+12) {
        int i=id-nav_id;
        if (page_==i || pressed) {
            box(dc,all,RGB(231,231,231),RGB(231,231,231),px(8));
            fill(dc,rect(1,h/2-8,4,h/2+8),accent);
        }
        glyph(nav_icons[i],disabled?RGB(139,139,139):page_==i?accent:ink,7,0,28,h);
        if (!compact_) text(1,disabled?RGB(130,130,130):ink,42,0,w-4,h,sections[i]);
    } else if (id>=metric_id && id<metric_id+7) {
        int i=id-metric_id;auto& f=data_.metrics[i];panel();
        if (i<2) {
            glyph(i?0xe74a:0xe74b,accent,12,8,24,23);
            text(1,muted,41,7,w-16,32,f.label);
            int chart_top=std::min(83,h-34);
            text(4,ink,17,30,w-15,chart_top,f.value+(f.value==L"—"?L"":L" "+std::wstring(units[i])));
            const auto& pts=data_.lines[i];
            if (pts.empty()) text(5,muted,17,chart_top,w-14,h-6,L"Brak próbek wykresu");
            else {
                double peak=0;for(auto p:pts) peak=std::max(peak,p.mbps);
                auto ceiling=std::max(1.0,std::ceil(peak/10.0)*10.0);
                int left=17,right=w-57,top=chart_top+1,bottom=h-19;
                auto x=[&](double t){return left+static_cast<int>((right-left)*t/std::max(.001,pts.back().seconds));};
                auto y=[&](double n){return bottom-static_cast<int>((bottom-top)*n/ceiling);};
                std::vector<POINT> coords;
                for(auto p:pts) coords.push_back({px(x(p.seconds)),px(y(p.mbps))});
                auto polygon=coords;polygon.push_back({coords.back().x,px(bottom)});polygon.push_back({coords.front().x,px(bottom)});
                SelectObject(dc,GetStockObject(NULL_PEN));SelectObject(dc,GetStockObject(DC_BRUSH));SetDCBrushColor(dc,RGB(229,241,250));
                Polygon(dc,polygon.data(),static_cast<int>(polygon.size()));
                for (int j=0;j<=2;++j) {int sy=px(top+(bottom-top)*j/2);line(dc,px(left),sy,px(right),sy,border);}
                for(int j=1;j<=3;++j){int sx=px(left+(right-left)*j/4);line(dc,sx,px(top),sx,px(bottom),RGB(234,234,234));}
                SelectObject(dc,GetStockObject(DC_PEN));SetDCPenColor(dc,accent);Polyline(dc,coords.data(),static_cast<int>(coords.size()));
                text(5,muted,right+4,top-8,w-4,top+9,number(ceiling));
                text(5,muted,left,bottom,right,h,L"0 s");
                text(5,muted,left,bottom,right,h,number(pts.back().seconds)+L" s",DT_RIGHT);
            }
        } else {
            text(0,muted,10,4,w-5,h/2,f.label);
            text(2,ink,10,h/2-4,w-5,h-4,f.value+(f.value==L"—"?L"":L" "+std::wstring(units[i])));
        }
    } else if (id>=check_id && id<check_id+10) {
        const int i=id-check_id;const auto& f=data_.checks[i];panel();
        glyph(check_icons[i],muted,8,0,24,h);
        if(i>=5 && i<=7 && f.value.size()>26){
            text(0,ink,38,1,w-25,h/2+2,f.label);
            text(0,tone_color(f.tone),38,h/2,w-25,h-1,f.value);
        }else{
            text(0,ink,38,0,w*53/100,h,f.label);
            text(0,tone_color(f.tone),w*53/100,0,w-24,h,f.value,DT_RIGHT);
        }
        glyph(0xe76c,muted,w-22,0,17,h);
    } else if (id==finding_id) {
        panel();glyph(0xe946,tone_color(data_.finding_tone),10,0,24,h);
        if (!data_.action.empty() && h>=36) {
            text(1,ink,41,1,w-28,h/2+2,data_.finding);
            text(5,muted,41,h/2,w-28,h-1,data_.action);
        } else text(1,ink,41,0,w-28,h,data_.finding);
        glyph(0xe76c,muted,w-25,0,18,h);
    } else if (id==menu_id) {
        glyph(0xe700,ink,1,0,w-2,h);
    } else {
        bool primary=id==start_id || id==stop_id || id==action_id;
        panel(primary?(pressed?RGB(0,81,152):accent):surface,primary?accent:border);
        auto color=primary?surface:disabled?muted:ink;
        if (primary) {
            glyph(id!=stop_id?0xe768:0xe71a,color,8,0,25,h);
            text(1,color,36,0,w-7,h,window_text(item.hwndItem));
        } else text(0,color,5,0,w-5,h,window_text(item.hwndItem),DT_CENTER);
    }
    if ((item.itemState&ODS_FOCUS) && !(item.itemState&ODS_NOFOCUSRECT)) {
        auto r=rect(3,3,w-3,h-3);DrawFocusRect(dc,&r);
    }
    BitBlt(item.hDC,0,0,ww,hh,dc,0,0,SRCCOPY);SelectObject(dc,old);DeleteObject(bmp);DeleteDC(dc);return true;
}
void View::hover(HWND card,int x) {
    const int dir=GetDlgCtrlID(card)-metric_id;
    const auto& line=data_.lines[dir];
    if (line.empty()) return;
    RECT r{};GetClientRect(card,&r);
    const auto fraction=std::clamp((x-px(17))/static_cast<double>(std::max(1L,r.right-px(74))),0.0,1.0);
    auto it=std::lower_bound(line.begin(),line.end(),fraction*line.back().seconds,
                             [](const Point& p,double t){return p.seconds<t;});
    if (it!=line.end()) hint(card,number(it->seconds)+L" s   ·   "+number(it->mbps)+L" Mb/s");
}
void View::choices(int id,const std::vector<std::wstring>& names,int select){
    auto w=GetDlgItem(parent_,id);SendMessageW(w,CB_RESETCONTENT,0,0);
    for(const auto& name:names)SendMessageW(w,CB_ADDSTRING,0,reinterpret_cast<LPARAM>(name.c_str()));
    SendMessageW(w,CB_SETCURSEL,select,0);
}
int View::selected() const {return ListView_GetNextItem(table_,-1,LVNI_SELECTED);}
void View::select_row(){
    int i=selected();set(graph_,i>=0 && static_cast<size_t>(i)<table_data_.rows.size()?table_data_.rows[i].detail:L"Brak zebranych wyników.");
    EnableWindow(copy_row_,i>=0);
    InvalidateRect(graph_,nullptr,FALSE);
}
void View::table(DetailPage page){
    auto index=selected();
    SendMessageW(table_,WM_SETREDRAW,FALSE,0);
    ListView_DeleteAllItems(table_);
    if(table_data_.columns!=page.columns){
        while(ListView_DeleteColumn(table_,0)){}
        for(size_t i=0;i<page.columns.size();++i){
            auto& [label,width]=page.columns[i];LVCOLUMNW col{};col.mask=LVCF_TEXT|LVCF_WIDTH;col.cx=px(width);col.pszText=label.data();
            ListView_InsertColumn(table_,static_cast<int>(i),&col);
        }
    }
    bool layout_change=table_data_.rows.empty()!=page.rows.empty() || std::min<size_t>(3,table_data_.rows.size())!=std::min<size_t>(3,page.rows.size());
    table_data_=std::move(page);
    for(size_t i=0;i<facts_.size();++i){
        if(i<table_data_.rows.size() && table_data_.rows[i].cells.size()>1)set(facts_[i],table_data_.rows[i].cells[0]+L"  "+table_data_.rows[i].cells[1]);
        InvalidateRect(facts_[i],nullptr,FALSE);
    }
    for(size_t i=0;i<table_data_.rows.size();++i){
        auto& row=table_data_.rows[i].cells;
        for(size_t c=0;c<row.size();++c){
            LVITEMW item{};item.mask=LVIF_TEXT;item.iItem=static_cast<int>(i);item.iSubItem=static_cast<int>(c);item.pszText=row[c].data();
            if(c==0)ListView_InsertItem(table_,&item);else SendMessageW(table_,LVM_SETITEMTEXTW,i,reinterpret_cast<LPARAM>(&item));
        }
    }
    if(!table_data_.rows.empty()){
        index=std::clamp(index,0,static_cast<int>(table_data_.rows.size()-1));
        ListView_SetItemState(table_,index,LVIS_SELECTED|LVIS_FOCUSED,LVIS_SELECTED|LVIS_FOCUSED);
    }
    SendMessageW(table_,WM_SETREDRAW,TRUE,0);InvalidateRect(table_,nullptr,TRUE);select_row();refresh_labels();if(layout_change)layout();
}
void View::sort(int column){
    if(column<0 || static_cast<size_t>(column)>=table_data_.columns.size())return;
    descending_=sort_col_==column && !descending_;sort_col_=column;
    auto p=table_data_;
    auto numeric=[](std::wstring v)->std::optional<double>{std::replace(v.begin(),v.end(),L',',L'.');wchar_t* end{};auto n=wcstod(v.c_str(),&end);return end!=v.c_str() && !*end?std::optional<double>(n):std::nullopt;};
    std::stable_sort(p.rows.begin(),p.rows.end(),[&](const DetailRow& a,const DetailRow& b){
        auto& av=a.cells.at(column);auto& bv=b.cells.at(column);auto an=numeric(av),bn=numeric(bv);
        if(an.has_value()!=bn.has_value())return an.has_value();
        if(an)return descending_?*bn<*an:*an<*bn;
        return descending_?bv<av:av<bv;
    });table(std::move(p));
}
void View::workspace(int nav,DetailPage page){
    report_status_.clear();workspace_=true;page_=nav;sort_col_=-1;descending_=false;
    set(title_,sections[nav]);table(std::move(page));layout();SetFocus(nav_[nav]);
}
void View::route_controls(bool enabled){
    for(auto w:{target_,choice_,region_,mode_,limit_,interval_,family_,favorite_,saved_,game_method_,game_length_})EnableWindow(w,enabled);
    set(action_,enabled?L"Wykonaj test":L"Zatrzymaj");
}
void View::report_source(const std::wstring& status,bool available){
    report_status_=status;EnableWindow(report_,available && !busy_);refresh_labels();
}
void View::route_status(const std::wstring& label){table_data_.subtitle=label;refresh_labels();}
void View::destroy() {if(logo_)DestroyIcon(logo_);for(auto f:fonts_) if(f) DeleteObject(f);}
}
