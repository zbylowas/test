#pragma once
#include "detail_pages.hpp"
#include <commctrl.h>
#include <string_view>
#include <map>

namespace summary {
constexpr int start_id=101, copy_id=102, stop_id=103, report_id=105, profile_id=106,
    menu_id=107, back_id=108, help_id=109, nav_id=200, metric_id=240, check_id=250, finding_id=261;
constexpr int list_id=310, graph_id=311, target_id=312, choice_id=313, mode_id=314, action_id=315, region_id=316, limit_id=317, interval_id=318, export_id=319, family_id=324, favorite_id=325, saved_id=326, game_method_id=327, game_length_id=328, compare_id=329, archive_id=330, update_id=331, copy_row_id=332, refresh_live_id=333;
class View {
public:
    void create(HWND window,std::wstring origin,std::wstring brand);
    void scale(UINT dpi);
    void layout();
    void update(const Snapshot& snapshot);
    void phase(const std::wstring& label);
    void controls(bool busy,bool has_code,bool has_details);
    void live(size_t direction,const Json& counters);
    void toggle_rail();
    void scroll(int command);
    void details(int nav,const std::wstring& caption,const std::wstring& content);
    void home();
    void workspace(int nav, DetailPage page);
    void table(DetailPage page);
    void select_row();
    void sort(int column);
    void choices(int id,const std::vector<std::wstring>& names,int select=0);
    int page() const {return page_;}
    const DetailPage& table_data() const {return table_data_;}
    int selected() const;
    void route_controls(bool enabled);
    void report_source(const std::wstring& status,bool available);
    void route_status(const std::wstring& label);

    bool draw(const DRAWITEMSTRUCT& item);
    void background(HDC dc);
    void destroy();
    bool capacity() const;
    void hover(HWND card,int x);
    int px(int value) const;
    const Snapshot& data() const {return data_;}
private:
    HICON logo_{};
    HWND parent_{},tools_{},profile_{},detail_{},title_{},sub_{},brand_{},footer_{},time_{},measurement_{},diagnostics_{};
    HWND compare_{},archive_{},update_{},copy_row_{},refresh_live_{};
    HWND game_method_{},game_length_{},family_{},favorite_{},saved_{};
    HWND table_{},graph_{},target_{},choice_{},mode_{},action_{},region_{},limit_{},interval_{},export_{};
    DetailPage table_data_;
    bool workspace_{},descending_{};
    int sort_col_=-1;
    HWND start_{},stop_{},copy_{},report_{},menu_{},back_{},profile_label_{},finding_{};
    std::array<HWND,3> facts_{};
    std::array<HWND,12> nav_{};
    std::array<HWND,7> metrics_{};
    std::array<HWND,10> checks_{};
    std::array<HFONT,8> fonts_{};
    std::map<HWND,std::wstring> tips_;
    UINT dpi_=96;
    bool collapsed_{},busy_{};
    int page_=0,offset_=0,scroll_limit_=0;
    bool compact_{};
    Snapshot data_;
    std::wstring origin_,brand_name_,operation_,report_status_;
    HWND child(const wchar_t* type,const wchar_t* caption,DWORD style,int id);
    HWND button(const wchar_t* name,int id);
    HWND label(const wchar_t* name);
    void refresh_labels();
    void hint(HWND window,const std::wstring& text);
    void move(HWND w,int x,int y,int width,int height,bool show=true);
};
}
