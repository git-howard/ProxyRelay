#include "MainWindow.h"
#include "ProxyServer.h"
#include "Database.h"
#include "TrafficMonitor.h"
#include "ConnectionLogger.h"
#include "Rules.h"
#include "Utils.h"
#include "Version.h"
#include <windowsx.h>
#include <uxtheme.h>
#include <dwmapi.h>
#include <gdiplus.h>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "uxtheme.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "gdiplus.lib")

using namespace Gdiplus;

// 颜色定义 - 亮色主题
const COLORREF COLOR_BG = RGB(240, 240, 240);       // 窗口背景 - 浅灰
const COLORREF COLOR_SURFACE = RGB(255, 255, 255);  // 控件背景 - 白色
const COLORREF COLOR_TEXT = RGB(0, 0, 0);           // 文本 - 黑色
const COLORREF COLOR_ACCENT = RGB(0, 102, 204);     // 强调色 - 蓝色
const COLORREF COLOR_GREEN = RGB(34, 139, 34);      // 绿色
const COLORREF COLOR_RED = RGB(220, 53, 69);        // 红色
const COLORREF COLOR_UPLOAD = RGB(255, 140, 0);     // 上传 - 橙色
const COLORREF COLOR_DOWNLOAD = RGB(0, 128, 128);   // 下载 - 青色

MainWindow& MainWindow::Instance() {
    static MainWindow instance;
    return instance;
}

MainWindow::~MainWindow() {
    RemoveTrayIcon();
}

bool MainWindow::Create(HINSTANCE hInstance) {
    hInstance_ = hInstance;
    
    // 初始化通用控件
    INITCOMMONCONTROLSEX icex = {sizeof(icex), ICC_TAB_CLASSES | ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES | ICC_LINK_CLASS};
    InitCommonControlsEx(&icex);
    
    // 注册窗口类
    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = CreateSolidBrush(COLOR_BG);
    wc.lpszClassName = L"ProxyRelayWindow";
    // 加载应用程序图标
    wc.hIcon = (HICON)LoadImageW(hInstance, MAKEINTRESOURCEW(1), IMAGE_ICON, 0, 0, LR_DEFAULTSIZE);
    if (!wc.hIcon) wc.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
    wc.hIconSm = wc.hIcon;
    
    if (!RegisterClassExW(&wc)) return false;
    
    // 创建窗口
    std::wstring windowTitle = Version::GetFullTitleW();
    hwnd_ = CreateWindowExW(
        0,
        L"ProxyRelayWindow",
        windowTitle.c_str(),
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 1000, 700,
        nullptr, nullptr, hInstance, this
    );
    
    if (!hwnd_) return false;
    
    // 创建菜单栏
    HMENU hMenuBar = CreateMenu();
    HMENU hSettingsMenu = CreatePopupMenu();
    AppendMenuW(hSettingsMenu, MF_STRING | (IsAutoStartEnabled() ? MF_CHECKED : 0), 
                ID_MENU_AUTOSTART, L"开机自启动(&A)");
    AppendMenuW(hSettingsMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hSettingsMenu, MF_STRING, ID_MENU_EXIT, L"退出(&X)");
    AppendMenuW(hMenuBar, MF_POPUP, (UINT_PTR)hSettingsMenu, L"设置(&S)");
    AppendMenuW(hMenuBar, MF_STRING, ID_MENU_ABOUT, L"关于(&A)");
    SetMenu(hwnd_, hMenuBar);
    
    // 禁用DWM暗色模式（使用亮色主题）
    BOOL darkMode = FALSE;
    DwmSetWindowAttribute(hwnd_, 20, &darkMode, sizeof(darkMode));
    
    // 创建托盘图标
    CreateTrayIcon();
    
    ShowWindow(hwnd_, SW_SHOW);
    UpdateWindow(hwnd_);
    
    return true;
}

int MainWindow::Run() {
    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return (int)msg.wParam;
}

LRESULT CALLBACK MainWindow::WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    MainWindow* self = nullptr;
    
    if (msg == WM_NCCREATE) {
        auto cs = reinterpret_cast<CREATESTRUCT*>(lParam);
        self = static_cast<MainWindow*>(cs->lpCreateParams);
        SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
        self->hwnd_ = hwnd;
        // Must call DefWindowProc for WM_NCCREATE
        return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    
    self = reinterpret_cast<MainWindow*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
    
    if (self) {
        return self->HandleMessage(msg, wParam, lParam);
    }
    
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

LRESULT MainWindow::HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE:
        CreateControls();
        SetTimer(hwnd_, IDT_REFRESH, 1000, nullptr);
        SetTimer(hwnd_, IDT_TRAFFIC_GRAPH, 1000, nullptr);
        return 0;
        
    case WM_SIZE:
        OnSize(LOWORD(lParam), HIWORD(lParam));
        return 0;
        
    case WM_COMMAND:
        OnCommand(wParam);
        return 0;
        
    case WM_NOTIFY: {
        auto nmhdr = reinterpret_cast<NMHDR*>(lParam);
        if (nmhdr->hwndFrom == hTab_ && nmhdr->code == TCN_SELCHANGE) {
            OnTabChange();
        }
        // 用户列表右键菜单
        else if (nmhdr->hwndFrom == hUserList_ && nmhdr->code == NM_RCLICK) {
            int sel = ListView_GetNextItem(hUserList_, -1, LVNI_SELECTED);
            if (sel >= 0) {
                POINT pt;
                GetCursorPos(&pt);
                HMENU hMenu = CreatePopupMenu();
                AppendMenuW(hMenu, MF_STRING, ID_CTX_EDIT, L"修改");
                AppendMenuW(hMenu, MF_STRING, ID_CTX_TOGGLE, L"暂停/启用");
                AppendMenuW(hMenu, MF_SEPARATOR, 0, nullptr);
                AppendMenuW(hMenu, MF_STRING, ID_CTX_MOVE_UP, L"上移");
                AppendMenuW(hMenu, MF_STRING, ID_CTX_MOVE_DOWN, L"下移");
                AppendMenuW(hMenu, MF_SEPARATOR, 0, nullptr);
                AppendMenuW(hMenu, MF_STRING, ID_CTX_DELETE, L"删除");
                SetForegroundWindow(hwnd_);
                UINT cmd = TrackPopupMenu(hMenu, TPM_RETURNCMD | TPM_NONOTIFY, pt.x, pt.y, 0, hwnd_, nullptr);
                DestroyMenu(hMenu);
                if (cmd == ID_CTX_EDIT) ShowEditUserDialog();
                else if (cmd == ID_CTX_DELETE) DeleteSelectedUser();
                else if (cmd == ID_CTX_TOGGLE) ToggleSelectedUser();
                else if (cmd == ID_CTX_MOVE_UP) MoveSelectedUserUp();
                else if (cmd == ID_CTX_MOVE_DOWN) MoveSelectedUserDown();
            }
        }
        // 端口列表右键菜单
        else if (nmhdr->hwndFrom == hPortList_ && nmhdr->code == NM_RCLICK) {
            int sel = ListView_GetNextItem(hPortList_, -1, LVNI_SELECTED);
            if (sel >= 0) {
                POINT pt;
                GetCursorPos(&pt);
                HMENU hMenu = CreatePopupMenu();
                AppendMenuW(hMenu, MF_STRING, ID_CTX_EDIT, L"修改");
                AppendMenuW(hMenu, MF_STRING, ID_CTX_TOGGLE, L"暂停/启用");
                AppendMenuW(hMenu, MF_SEPARATOR, 0, nullptr);
                AppendMenuW(hMenu, MF_STRING, ID_CTX_MOVE_UP, L"上移");
                AppendMenuW(hMenu, MF_STRING, ID_CTX_MOVE_DOWN, L"下移");
                AppendMenuW(hMenu, MF_SEPARATOR, 0, nullptr);
                AppendMenuW(hMenu, MF_STRING, ID_CTX_DELETE, L"删除");
                SetForegroundWindow(hwnd_);
                UINT cmd = TrackPopupMenu(hMenu, TPM_RETURNCMD | TPM_NONOTIFY, pt.x, pt.y, 0, hwnd_, nullptr);
                DestroyMenu(hMenu);
                if (cmd == ID_CTX_EDIT) ShowEditPortDialog();
                else if (cmd == ID_CTX_DELETE) DeleteSelectedPort();
                else if (cmd == ID_CTX_TOGGLE) ToggleSelectedPort();
                else if (cmd == ID_CTX_MOVE_UP) MoveSelectedPortUp();
                else if (cmd == ID_CTX_MOVE_DOWN) MoveSelectedPortDown();
            }
        }
        // 封禁列表右键菜单
        else if (nmhdr->hwndFrom == hBanList_ && nmhdr->code == NM_RCLICK) {
            int sel = ListView_GetNextItem(hBanList_, -1, LVNI_SELECTED);
            if (sel >= 0) {
                POINT pt;
                GetCursorPos(&pt);
                HMENU hMenu = CreatePopupMenu();
                if (currentBanType_ != 2) { // 自动封禁不显示编辑
                    AppendMenuW(hMenu, MF_STRING, ID_CTX_EDIT, L"修改");
                }
                AppendMenuW(hMenu, MF_STRING, ID_CTX_DELETE, L"删除/解封");
                SetForegroundWindow(hwnd_);
                UINT cmd = TrackPopupMenu(hMenu, TPM_RETURNCMD | TPM_NONOTIFY, pt.x, pt.y, 0, hwnd_, nullptr);
                DestroyMenu(hMenu);
                if (cmd == ID_CTX_EDIT) ShowEditBanDialog();
                else if (cmd == ID_CTX_DELETE) DeleteSelectedBan();
            }
        }
        // 日志列表右键菜单
        else if (nmhdr->hwndFrom == hLogList_ && nmhdr->code == NM_RCLICK) {
            int sel = ListView_GetNextItem(hLogList_, -1, LVNI_SELECTED);
            if (sel >= 0) {
                POINT pt;
                GetCursorPos(&pt);
                HMENU hMenu = CreatePopupMenu();
                AppendMenuW(hMenu, MF_STRING, ID_CTX_COPY_IP, L"复制客户端IP");
                AppendMenuW(hMenu, MF_STRING, ID_CTX_COPY_ADDRESS, L"复制目标地址");
                SetForegroundWindow(hwnd_);
                UINT cmd = TrackPopupMenu(hMenu, TPM_RETURNCMD | TPM_NONOTIFY, pt.x, pt.y, 0, hwnd_, nullptr);
                DestroyMenu(hMenu);
                
                if (cmd == ID_CTX_COPY_IP) {
                    wchar_t buf[256];
                    ListView_GetItemText(hLogList_, sel, 3, buf, 256); // 列3是客户端IP
                    Utils::CopyToClipboard(buf);
                } else if (cmd == ID_CTX_COPY_ADDRESS) {
                    wchar_t buf[256];
                    ListView_GetItemText(hLogList_, sel, 4, buf, 256); // 列4是目标地址
                    Utils::CopyToClipboard(buf);
                }
            }
        }
        return 0;
    }
        
    case WM_TIMER:
        OnTimer(wParam);
        return 0;
        
    case WM_DRAWITEM: {
        auto dis = reinterpret_cast<DRAWITEMSTRUCT*>(lParam);
        if (dis->hwndItem == hTrafficGraph_) {
            DrawTrafficGraph(dis->hDC, dis->rcItem);
            return TRUE;
        }
        break;
    }
    
    case WM_ADD_LOG_ENTRY: {
        // 日志条目已添加到ConnectionLogger，只需刷新UI
        if (currentTab_ == 3 && hLogList_) {
            auto entry = reinterpret_cast<ConnectionLogEntry*>(lParam);
            if (entry) {
                // 插入新条目到列表顶部
                LVITEMW lvi = {};
                lvi.mask = LVIF_TEXT;
                lvi.iItem = 0;
                std::wstring ts = Utils::StringToWString(entry->timestamp);
                lvi.pszText = (LPWSTR)ts.c_str();
                int idx = ListView_InsertItem(hLogList_, &lvi);
                
                std::wstring user = Utils::StringToWString(entry->username);
                ListView_SetItemText(hLogList_, idx, 1, (LPWSTR)user.c_str());
                
                std::wstring proxy = Utils::StringToWString(entry->proxyDesc);
                ListView_SetItemText(hLogList_, idx, 2, (LPWSTR)proxy.c_str());

                std::wstring ip = Utils::StringToWString(entry->clientIP);
                ListView_SetItemText(hLogList_, idx, 3, (LPWSTR)ip.c_str());
                
                std::wstring target = Utils::StringToWString(entry->targetHost + ":" + std::to_string(entry->targetPort));
                ListView_SetItemText(hLogList_, idx, 4, (LPWSTR)target.c_str());
                
                std::wstring action = Utils::StringToWString(entry->action);
                ListView_SetItemText(hLogList_, idx, 5, (LPWSTR)action.c_str());
                
                // 删除传递的副本
                delete entry;
                
                // 限制列表项数量为最近100条
                while (ListView_GetItemCount(hLogList_) > 100) {
                    ListView_DeleteItem(hLogList_, ListView_GetItemCount(hLogList_) - 1);
                }
            }
        } else {
            // 如果不在日志页面，仍然需要删除传递的副本
            auto entry = reinterpret_cast<ConnectionLogEntry*>(lParam);
            if (entry) delete entry;
        }
        return 0;
    }
        
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORBTN: {
        HDC hdc = (HDC)wParam;
        SetTextColor(hdc, COLOR_TEXT);
        SetBkColor(hdc, COLOR_SURFACE);
        static HBRUSH brush = CreateSolidBrush(COLOR_SURFACE);
        return (LRESULT)brush;
    }
    
    case WM_TRAYICON:
        if (lParam == WM_LBUTTONDBLCLK) {
            RestoreFromTray();
        } else if (lParam == WM_RBUTTONUP) {
            ShowTrayMenu();
        }
        return 0;
    
    case WM_SYSCOMMAND:
        if (wParam == SC_MINIMIZE) {
            MinimizeToTray();
            return 0;
        }
        break;
    
    case WM_CLOSE:
        // 点击关闭按钮时隐藏到托盘而不是退出
        MinimizeToTray();
        return 0;
        
    case WM_DESTROY:
        RemoveTrayIcon();
        KillTimer(hwnd_, IDT_REFRESH);
        KillTimer(hwnd_, IDT_TRAFFIC_GRAPH);
        PostQuitMessage(0);
        return 0;
    }
    
    return DefWindowProc(hwnd_, msg, wParam, lParam);
}

void MainWindow::CreateControls() {
    // 创建字体
    HFONT hFont = CreateFontW(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei UI");
    
    // 创建Tab控件 - 填充整个窗口区域
    RECT clientRect;
    GetClientRect(hwnd_, &clientRect);
    hTab_ = CreateWindowW(WC_TABCONTROLW, L"",
        WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS,
        0, 0, clientRect.right, clientRect.bottom - 25, 
        hwnd_, (HMENU)IDC_TAB_MAIN, hInstance_, nullptr);
    SendMessage(hTab_, WM_SETFONT, (WPARAM)hFont, TRUE);
    
    // 添加Tab页
    TCITEMW tie = {};
    tie.mask = TCIF_TEXT;
    
    tie.pszText = (LPWSTR)L"用户管理";
    TabCtrl_InsertItem(hTab_, 0, &tie);
    
    tie.pszText = (LPWSTR)L"代理配置";
    TabCtrl_InsertItem(hTab_, 1, &tie);
    
    tie.pszText = (LPWSTR)L"流量统计";
    TabCtrl_InsertItem(hTab_, 2, &tie);
    
    tie.pszText = (LPWSTR)L"连接日志";
    TabCtrl_InsertItem(hTab_, 3, &tie);
    
    tie.pszText = (LPWSTR)L"封禁管理";
    TabCtrl_InsertItem(hTab_, 4, &tie);
    
    tie.pszText = (LPWSTR)L"路由策略";
    TabCtrl_InsertItem(hTab_, 5, &tie);
    
    tie.pszText = (LPWSTR)L"系统设置";
    TabCtrl_InsertItem(hTab_, 6, &tie);
    
    CreateUserPage();
    CreatePortPage();
    CreateTrafficPage();
    CreateLogPage();
    
    // 初始化规则（必须在创建黑名单/Bypass页面之前）
    RuleManager::Instance().Initialize();
    
    CreateBanPage();
    CreateBypassPage();
    CreateSettingsPage();
    CreateStatusBar();
    
    // Create ToolTip
    hToolTip_ = Utils::CreateToolTip(hwnd_);
    
    OnTabChange();
    RefreshUserList();
    RefreshPortList();
    
    // 自动启动服务
    ProxyServer::Instance().Start();
    TrafficMonitor::Instance().Start();
    UpdateStatus();
}

void MainWindow::CreateUserPage() {
    HFONT hFont = CreateFontW(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei UI");
    
    // 获取Tab内容区域相对于主窗口的位置
    RECT tabClientRect;
    GetWindowRect(hTab_, &tabClientRect);
    MapWindowPoints(HWND_DESKTOP, hwnd_, (LPPOINT)&tabClientRect, 2);
    
    RECT tabRect;
    GetClientRect(hTab_, &tabRect);
    TabCtrl_AdjustRect(hTab_, FALSE, &tabRect);
    
    // 转换为相对于主窗口的坐标
    int left = tabClientRect.left + tabRect.left + 10;
    int top = tabClientRect.top + tabRect.top + 5;
    int width = tabRect.right - tabRect.left - 20;
    int listHeight = tabRect.bottom - tabRect.top - 50;
    int btnTop = tabClientRect.top + tabRect.bottom - 40;
    
    // 用户列表
    hUserList_ = CreateWindowExW(0, WC_LISTVIEWW, L"",
        WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | WS_BORDER,
        left, top, width, listHeight, 
        hwnd_, (HMENU)IDC_LIST_USERS, hInstance_, nullptr);
    
    ListView_SetExtendedListViewStyle(hUserList_, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
    ListView_SetBkColor(hUserList_, COLOR_SURFACE);
    ListView_SetTextBkColor(hUserList_, COLOR_SURFACE);
    ListView_SetTextColor(hUserList_, COLOR_TEXT);
    SendMessage(hUserList_, WM_SETFONT, (WPARAM)hFont, TRUE);
    SetWindowTheme(hUserList_, L"", L"");
    
    // 列
    LVCOLUMNW lvc = {};
    lvc.mask = LVCF_TEXT | LVCF_WIDTH;
    
    lvc.pszText = (LPWSTR)L"ID"; lvc.cx = 50;
    ListView_InsertColumn(hUserList_, 0, &lvc);
    
    lvc.pszText = (LPWSTR)L"用户名"; lvc.cx = 120;
    ListView_InsertColumn(hUserList_, 1, &lvc);
    
    lvc.pszText = (LPWSTR)L"允许IP"; lvc.cx = 150;
    ListView_InsertColumn(hUserList_, 2, &lvc);
    
    lvc.pszText = (LPWSTR)L"每日限额"; lvc.cx = 100;
    ListView_InsertColumn(hUserList_, 3, &lvc);
    
    lvc.pszText = (LPWSTR)L"每月限额"; lvc.cx = 100;
    ListView_InsertColumn(hUserList_, 4, &lvc);
    
    lvc.pszText = (LPWSTR)L"今日用量"; lvc.cx = 100;
    ListView_InsertColumn(hUserList_, 5, &lvc);
    
    lvc.pszText = (LPWSTR)L"本月用量"; lvc.cx = 100;
    ListView_InsertColumn(hUserList_, 6, &lvc);
    
    lvc.pszText = (LPWSTR)L"上月用量"; lvc.cx = 100;
    ListView_InsertColumn(hUserList_, 7, &lvc);
    
    lvc.pszText = (LPWSTR)L"总流量"; lvc.cx = 100;
    ListView_InsertColumn(hUserList_, 8, &lvc);
    
    lvc.pszText = (LPWSTR)L"备注"; lvc.cx = 150;
    ListView_InsertColumn(hUserList_, 9, &lvc);
    
    lvc.pszText = (LPWSTR)L"到期日期"; lvc.cx = 100;
    ListView_InsertColumn(hUserList_, 10, &lvc);
    
    lvc.pszText = (LPWSTR)L"状态"; lvc.cx = 80;
    ListView_InsertColumn(hUserList_, 11, &lvc);
    
    // 按钮
    HWND hBtn = CreateWindowW(L"BUTTON", L"添加用户",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        left, btnTop, 100, 30, hwnd_, (HMENU)IDC_BTN_ADD_USER, hInstance_, nullptr);
    SendMessage(hBtn, WM_SETFONT, (WPARAM)hFont, TRUE);
    Utils::SetToolTip(hToolTip_, hBtn, L"新增一个代理用户，支持限速、每日限额等配置");
    
    hBtn = CreateWindowW(L"BUTTON", L"编辑用户",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        left + 110, btnTop, 100, 30, hwnd_, (HMENU)IDC_BTN_EDIT_USER, hInstance_, nullptr);
    SendMessage(hBtn, WM_SETFONT, (WPARAM)hFont, TRUE);
    Utils::SetToolTip(hToolTip_, hBtn, L"修改选中用户的配置信息");
    
    hBtn = CreateWindowW(L"BUTTON", L"删除用户",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        left + 220, btnTop, 100, 30, hwnd_, (HMENU)IDC_BTN_DEL_USER, hInstance_, nullptr);
    SendMessage(hBtn, WM_SETFONT, (WPARAM)hFont, TRUE);
    Utils::SetToolTip(hToolTip_, hBtn, L"删除选中的用户账户");
}

void MainWindow::CreatePortPage() {
    HFONT hFont = CreateFontW(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei UI");
    
    // 获取Tab内容区域相对于主窗口的位置
    RECT tabClientRect;
    GetWindowRect(hTab_, &tabClientRect);
    MapWindowPoints(HWND_DESKTOP, hwnd_, (LPPOINT)&tabClientRect, 2);
    
    RECT tabRect;
    GetClientRect(hTab_, &tabRect);
    TabCtrl_AdjustRect(hTab_, FALSE, &tabRect);
    
    // 转换为相对于主窗口的坐标
    int left = tabClientRect.left + tabRect.left + 10;
    int top = tabClientRect.top + tabRect.top + 5;
    int width = tabRect.right - tabRect.left - 20;
    int listHeight = tabRect.bottom - tabRect.top - 50;
    int btnTop = tabClientRect.top + tabRect.bottom - 40;
    
    // 端口列表
    hPortList_ = CreateWindowExW(0, WC_LISTVIEWW, L"",
        WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | WS_BORDER,
        left, top, width, listHeight,
        hwnd_, (HMENU)IDC_LIST_PORTS, hInstance_, nullptr);
    
    ListView_SetExtendedListViewStyle(hPortList_, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
    ListView_SetBkColor(hPortList_, COLOR_SURFACE);
    ListView_SetTextBkColor(hPortList_, COLOR_SURFACE);
    ListView_SetTextColor(hPortList_, COLOR_TEXT);
    SendMessage(hPortList_, WM_SETFONT, (WPARAM)hFont, TRUE);
    SetWindowTheme(hPortList_, L"", L"");
    
    LVCOLUMNW lvc = {};
    lvc.mask = LVCF_TEXT | LVCF_WIDTH;
    
    lvc.pszText = (LPWSTR)L"ID"; lvc.cx = 50;
    ListView_InsertColumn(hPortList_, 0, &lvc);
    
    lvc.pszText = (LPWSTR)L"监听端口"; lvc.cx = 100;
    ListView_InsertColumn(hPortList_, 1, &lvc);
    
    lvc.pszText = (LPWSTR)L"上游类型"; lvc.cx = 100;
    ListView_InsertColumn(hPortList_, 2, &lvc);
    
    lvc.pszText = (LPWSTR)L"上游地址"; lvc.cx = 200;
    ListView_InsertColumn(hPortList_, 3, &lvc);
    
    lvc.pszText = (LPWSTR)L"上游端口"; lvc.cx = 100;
    ListView_InsertColumn(hPortList_, 4, &lvc);
    
    lvc.pszText = (LPWSTR)L"描述"; lvc.cx = 200;
    ListView_InsertColumn(hPortList_, 5, &lvc);
    
    lvc.pszText = (LPWSTR)L"状态"; lvc.cx = 80;
    ListView_InsertColumn(hPortList_, 6, &lvc);
    
    lvc.pszText = (LPWSTR)L"实时速度"; lvc.cx = 120;
    ListView_InsertColumn(hPortList_, 7, &lvc);
    
    lvc.pszText = (LPWSTR)L"1h流量"; lvc.cx = 120;
    ListView_InsertColumn(hPortList_, 8, &lvc);
    
    lvc.pszText = (LPWSTR)L"24h流量"; lvc.cx = 120;
    ListView_InsertColumn(hPortList_, 9, &lvc);
    
    lvc.pszText = (LPWSTR)L"本周流量"; lvc.cx = 120;
    ListView_InsertColumn(hPortList_, 10, &lvc);
    
    lvc.pszText = (LPWSTR)L"本月流量"; lvc.cx = 120;
    ListView_InsertColumn(hPortList_, 11, &lvc);
    
    lvc.pszText = (LPWSTR)L"上月流量"; lvc.cx = 120;
    ListView_InsertColumn(hPortList_, 12, &lvc);
    
    HWND hBtn = CreateWindowW(L"BUTTON", L"添加端口",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        left, btnTop, 100, 30, hwnd_, (HMENU)IDC_BTN_ADD_PORT, hInstance_, nullptr);
    SendMessage(hBtn, WM_SETFONT, (WPARAM)hFont, TRUE);
    Utils::SetToolTip(hToolTip_, hBtn, L"配置一个新的代理端端口及其上游。");
    
    hBtn = CreateWindowW(L"BUTTON", L"编辑端口",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        left + 110, btnTop, 100, 30, hwnd_, (HMENU)IDC_BTN_EDIT_PORT, hInstance_, nullptr);
    SendMessage(hBtn, WM_SETFONT, (WPARAM)hFont, TRUE);
    Utils::SetToolTip(hToolTip_, hBtn, L"修改选中代理端口信息的配置项。");
    
    hBtn = CreateWindowW(L"BUTTON", L"删除端口",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        left + 220, btnTop, 100, 30, hwnd_, (HMENU)IDC_BTN_DEL_PORT, hInstance_, nullptr);
    SendMessage(hBtn, WM_SETFONT, (WPARAM)hFont, TRUE);
    Utils::SetToolTip(hToolTip_, hBtn, L"删除选中的代理端口及其配置。");
}

void MainWindow::CreateTrafficPage() {
    HFONT hFont = CreateFontW(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei UI");
    
    // 获取Tab内容区域相对于主窗口的位置
    RECT tabClientRect;
    GetWindowRect(hTab_, &tabClientRect);
    MapWindowPoints(HWND_DESKTOP, hwnd_, (LPPOINT)&tabClientRect, 2);
    
    RECT tabRect;
    GetClientRect(hTab_, &tabRect);
    TabCtrl_AdjustRect(hTab_, FALSE, &tabRect);
    
    // 转换为相对于主窗口的坐标
    int left = tabClientRect.left + tabRect.left + 10;
    int top = tabClientRect.top + tabRect.top + 5;
    int width = tabRect.right - tabRect.left - 20;
    int graphHeight = 200;
    int listTop = top + graphHeight + 10;
    int listHeight = tabClientRect.top + tabRect.bottom - listTop - 10;
    
    // 实时流量显示区域 - 父窗口是hwnd_以接收WM_DRAWITEM
    hTrafficGraph_ = CreateWindowW(L"STATIC", L"",
        WS_CHILD | WS_VISIBLE | SS_OWNERDRAW | WS_BORDER,
        left, top, width, graphHeight,
        hwnd_, (HMENU)IDC_STATIC_TRAFFIC, hInstance_, nullptr);
    
    // 流量历史列表 - 父窗口是hwnd_
    hTrafficList_ = CreateWindowExW(0, WC_LISTVIEWW, L"",
        WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | WS_BORDER,
        left, listTop, width, listHeight,
        hwnd_, (HMENU)IDC_LIST_TRAFFIC, hInstance_, nullptr);
    
    ListView_SetExtendedListViewStyle(hTrafficList_, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
    ListView_SetBkColor(hTrafficList_, COLOR_SURFACE);
    ListView_SetTextBkColor(hTrafficList_, COLOR_SURFACE);
    ListView_SetTextColor(hTrafficList_, COLOR_TEXT);
    SendMessage(hTrafficList_, WM_SETFONT, (WPARAM)hFont, TRUE);
    SetWindowTheme(hTrafficList_, L"", L"");
    
    LVCOLUMNW lvc = {};
    lvc.mask = LVCF_TEXT | LVCF_WIDTH;
    
    lvc.pszText = (LPWSTR)L"用户"; lvc.cx = 90;     // 150 * 3/5
    ListView_InsertColumn(hTrafficList_, 0, &lvc);
    
    lvc.pszText = (LPWSTR)L"日期"; lvc.cx = 72;     // 120 * 3/5
    ListView_InsertColumn(hTrafficList_, 1, &lvc);
    
    lvc.pszText = (LPWSTR)L"1h上传"; lvc.cx = 60;   // 100 * 3/5
    ListView_InsertColumn(hTrafficList_, 2, &lvc);
    
    lvc.pszText = (LPWSTR)L"1h下载"; lvc.cx = 60;
    ListView_InsertColumn(hTrafficList_, 3, &lvc);
    
    lvc.pszText = (LPWSTR)L"24h上传"; lvc.cx = 60;
    ListView_InsertColumn(hTrafficList_, 4, &lvc);
    
    lvc.pszText = (LPWSTR)L"24h下载"; lvc.cx = 60;
    ListView_InsertColumn(hTrafficList_, 5, &lvc);
    
    lvc.pszText = (LPWSTR)L"今日上传"; lvc.cx = 60;
    ListView_InsertColumn(hTrafficList_, 6, &lvc);
    
    lvc.pszText = (LPWSTR)L"今日下载"; lvc.cx = 60;
    ListView_InsertColumn(hTrafficList_, 7, &lvc);
    
    lvc.pszText = (LPWSTR)L"本周上传"; lvc.cx = 60;
    ListView_InsertColumn(hTrafficList_, 8, &lvc);
    
    lvc.pszText = (LPWSTR)L"本周下载"; lvc.cx = 60;
    ListView_InsertColumn(hTrafficList_, 9, &lvc);
    
    lvc.pszText = (LPWSTR)L"本月上传"; lvc.cx = 60;
    ListView_InsertColumn(hTrafficList_, 10, &lvc);
    
    lvc.pszText = (LPWSTR)L"本月下载"; lvc.cx = 60;
    ListView_InsertColumn(hTrafficList_, 11, &lvc);
}

void MainWindow::CreateStatusBar() {
    hStatusBar_ = CreateWindowW(STATUSCLASSNAMEW, L"",
        WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
        0, 0, 0, 0, hwnd_, nullptr, hInstance_, nullptr);
    
    int parts[] = {200, 400, 600, -1};
    SendMessage(hStatusBar_, SB_SETPARTS, 4, (LPARAM)parts);
    
    UpdateStatus();
}

void MainWindow::OnSize(int width, int height) {
    if (hTab_) {
        MoveWindow(hTab_, 0, 0, width, height - 25, TRUE);
    }
    if (hStatusBar_) {
        SendMessage(hStatusBar_, WM_SIZE, 0, 0);
    }
}

void MainWindow::OnTabChange() {
    currentTab_ = TabCtrl_GetCurSel(hTab_);
    
    ShowWindow(hUserList_, currentTab_ == 0 ? SW_SHOW : SW_HIDE);
    ShowWindow(hPortList_, currentTab_ == 1 ? SW_SHOW : SW_HIDE);
    ShowWindow(hTrafficGraph_, currentTab_ == 2 ? SW_SHOW : SW_HIDE);
    ShowWindow(hTrafficList_, currentTab_ == 2 ? SW_SHOW : SW_HIDE);
    ShowWindow(hLogList_, currentTab_ == 3 ? SW_SHOW : SW_HIDE);
    
    // 显示/隐藏相应的按钮
    HWND btns[] = {
        GetDlgItem(hwnd_, IDC_BTN_ADD_USER), GetDlgItem(hwnd_, IDC_BTN_EDIT_USER), 
        GetDlgItem(hwnd_, IDC_BTN_DEL_USER),
        GetDlgItem(hwnd_, IDC_BTN_ADD_PORT), GetDlgItem(hwnd_, IDC_BTN_EDIT_PORT), 
        GetDlgItem(hwnd_, IDC_BTN_DEL_PORT)
    };
    
    for (int i = 0; i < 3; i++) {
        if (btns[i]) ShowWindow(btns[i], currentTab_ == 0 ? SW_SHOW : SW_HIDE);
    }
    for (int i = 3; i < 6; i++) {
        if (btns[i]) ShowWindow(btns[i], currentTab_ == 1 ? SW_SHOW : SW_HIDE);
    }
    
    // 页面可见性 (Ban Management Tab 4)
    BOOL showBan = (currentTab_ == 4);
    int banIds[] = {IDC_COMBO_BAN_TYPE, IDC_LIST_BAN, IDC_BTN_ADD_BAN, IDC_BTN_DEL_BAN,
                    IDC_EDIT_M, IDC_EDIT_N, IDC_EDIT_T, IDC_BTN_SAVE_BAN_SETTINGS,
                    IDC_STATIC_BAN_M, IDC_STATIC_BAN_N, IDC_STATIC_BAN_T, IDC_STATIC_BAN_MINUTES};
    for(int id : banIds) {
        HWND h = GetDlgItem(hwnd_, id);
        if (h) ShowWindow(h, showBan ? SW_SHOW : SW_HIDE);
    }
    
    if (showBan) {
         RefreshBanList(); // Refresh when tab is shown
    }
    
    // 页面可见性 (Bypass Tab 5)
    BOOL showBP = (currentTab_ == 5);
    int bpIds[] = {IDC_BTN_SAVE_BYPASS, 10020};
    for(int id : bpIds) {
        HWND h = GetDlgItem(hwnd_, id);
        if (h) ShowWindow(h, showBP ? SW_SHOW : SW_HIDE);
    }
    // 动态创建的路由规则编辑框
    for (const auto& edit : routingRuleEdits_) {
        if (edit.hLabel) ShowWindow(edit.hLabel, showBP ? SW_SHOW : SW_HIDE);
        if (edit.hEdit) ShowWindow(edit.hEdit, showBP ? SW_SHOW : SW_HIDE);
        if (edit.hPriorityLabel) ShowWindow(edit.hPriorityLabel, showBP ? SW_SHOW : SW_HIDE);
        if (edit.hPriorityEdit) ShowWindow(edit.hPriorityEdit, showBP ? SW_SHOW : SW_HIDE);
    }

    
    // 页面可见性 (Settings Tab 6)
    BOOL showSettings = (currentTab_ == 6);
    int stIds[] = {IDC_EDIT_SETTINGS_AUTO_PORT, IDC_EDIT_SETTINGS_TCPING, 
                   IDC_BTN_SAVE_SETTINGS, IDC_STATIC_SETTINGS_LABEL, IDC_STATIC_SETTINGS_TCPING,
                   IDC_EDIT_SETTINGS_LOG_DAYS, IDC_STATIC_SETTINGS_LOG_DAYS,
                   IDC_EDIT_SETTINGS_BUFFER_SIZE, IDC_STATIC_SETTINGS_BUFFER_SIZE, 10099};
    for(int id : stIds) {
        HWND h = GetDlgItem(hwnd_, id);
        if (h) ShowWindow(h, showSettings ? SW_SHOW : SW_HIDE);
    }
    
    // 切换到日志页面时刷新
    if (currentTab_ == 3) {
        RefreshLogList();
    }
}

void MainWindow::OnCommand(WPARAM wParam) {
    switch (LOWORD(wParam)) {
    case IDC_BTN_ADD_USER:
        ShowAddUserDialog();
        break;
        
    case IDC_BTN_EDIT_USER:
        ShowEditUserDialog();
        break;
        
    case IDC_BTN_DEL_USER:
        DeleteSelectedUser();
        break;
        
    case IDC_BTN_ADD_PORT:
        ShowAddPortDialog();
        break;
        
    case IDC_BTN_EDIT_PORT:
        ShowEditPortDialog();
        break;
        
    case IDC_BTN_DEL_PORT:
        DeleteSelectedPort();
        break;
        
    // 菜单命令
    case ID_MENU_AUTOSTART: {
        bool newState = !IsAutoStartEnabled();
        SetAutoStart(newState);
        // 更新菜单项勾选状态
        HMENU hMenu = GetMenu(hwnd_);
        HMENU hSubMenu = GetSubMenu(hMenu, 0);
        CheckMenuItem(hSubMenu, ID_MENU_AUTOSTART, MF_BYCOMMAND | (newState ? MF_CHECKED : MF_UNCHECKED));
        break;
    }
        
    case ID_MENU_ABOUT:
        ShowAboutDialog();
        break;
        
    case ID_MENU_EXIT:
        RemoveTrayIcon();
        DestroyWindow(hwnd_);
        break;
        
    case IDC_BTN_ADD_BAN:
        ShowAddBanDialog();
        break;
        
    case IDC_BTN_DEL_BAN:
        DeleteSelectedBan();
        break;
        
    case IDC_BTN_SAVE_BAN_SETTINGS:
        SaveBanSettings();
        break;
        
    case IDC_COMBO_BAN_TYPE:
        if (HIWORD(wParam) == CBN_SELCHANGE) {
            OnBanTypeChanged();
        }
        break;
        
    case IDC_BTN_SAVE_BYPASS:
        SaveBypassConfig();
        break;
        
    case IDC_BTN_SAVE_SETTINGS:
        SaveSettings();
        break;
    }
}

void MainWindow::OnTimer(WPARAM timerId) {
    if (timerId == IDT_REFRESH) {
        UpdateStatus();
    } else if (timerId == IDT_TRAFFIC_GRAPH) {
        RefreshTrafficGraph();
        if (currentTab_ == 1) {
            UpdatePortStats();
        }
    }
}

void MainWindow::UpdateStatus() {
    bool running = ProxyServer::Instance().IsRunning();
    auto ports = ProxyServer::Instance().GetListeningPorts();
    
    std::wstring status = running ? L"运行中" : L"已停止";
    SendMessageW(hStatusBar_, SB_SETTEXTW, 0, (LPARAM)status.c_str());
    
    // 显示监听端口
    std::wstring portStr = L"端口: ";
    for (size_t i = 0; i < ports.size(); i++) {
        if (i > 0) portStr += L", ";
        portStr += std::to_wstring(ports[i]);
    }
    
    // 添加自动代理端口显示
    std::string autoPortStr = Database::Instance().GetConfig("auto_proxy_port", "0");
    int autoPort = std::atoi(autoPortStr.c_str());
    if (autoPort > 0) {
        if (!ports.empty()) portStr += L" | ";
        portStr += L"自动: " + std::to_wstring(autoPort);
    }
    
    SendMessageW(hStatusBar_, SB_SETTEXTW, 1, (LPARAM)portStr.c_str());
    
    auto traffic = TrafficMonitor::Instance().GetCurrentData();
    std::wstring speedStr = L"↑ " + Utils::FormatBytesW(traffic.uploadSpeed) + L"/s  ↓ " + 
                            Utils::FormatBytesW(traffic.downloadSpeed) + L"/s";
    SendMessageW(hStatusBar_, SB_SETTEXTW, 2, (LPARAM)speedStr.c_str());
    
    int conns = ProxyServer::Instance().GetActiveConnections();
    std::wstring connStr = L"连接: " + std::to_wstring(conns);
    SendMessageW(hStatusBar_, SB_SETTEXTW, 3, (LPARAM)connStr.c_str());
}

void MainWindow::RefreshUserList() {
    ListView_DeleteAllItems(hUserList_);
    
    auto users = Database::Instance().GetAllUsers();
    int idx = 0;
    for (const auto& user : users) {
        LVITEMW lvi = {};
        lvi.mask = LVIF_TEXT;
        lvi.iItem = idx;
        
        std::wstring id = std::to_wstring(user.id);
        lvi.pszText = (LPWSTR)id.c_str();
        ListView_InsertItem(hUserList_, &lvi);
        
        std::wstring name = Utils::StringToWString(user.username);
        ListView_SetItemText(hUserList_, idx, 1, (LPWSTR)name.c_str());
        
        std::wstring ips = Utils::StringToWString(user.allowedIPs);
        ListView_SetItemText(hUserList_, idx, 2, (LPWSTR)ips.c_str());
        
        std::wstring daily = user.dailyLimit > 0 ? Utils::FormatBytesW(user.dailyLimit) : L"无限制";
        ListView_SetItemText(hUserList_, idx, 3, (LPWSTR)daily.c_str());
        
        std::wstring monthly = user.monthlyLimit > 0 ? Utils::FormatBytesW(user.monthlyLimit) : L"无限制";
        ListView_SetItemText(hUserList_, idx, 4, (LPWSTR)monthly.c_str());
        
        int64_t dailyUsage = Database::Instance().GetUserDailyUsage(user.id);
        std::wstring dailyUsageStr = Utils::FormatBytesW(dailyUsage);
        ListView_SetItemText(hUserList_, idx, 5, (LPWSTR)dailyUsageStr.c_str());
        
        int64_t monthlyUsage = Database::Instance().GetUserMonthlyUsage(user.id);
        std::wstring monthlyUsageStr = Utils::FormatBytesW(monthlyUsage);
        ListView_SetItemText(hUserList_, idx, 6, (LPWSTR)monthlyUsageStr.c_str());
        
        int64_t lastMonthUsage = Database::Instance().GetUserLastMonthUsage(user.id);
        std::wstring lastMonthUsageStr = Utils::FormatBytesW(lastMonthUsage);
        ListView_SetItemText(hUserList_, idx, 7, (LPWSTR)lastMonthUsageStr.c_str());
        
        int64_t totalUsage = Database::Instance().GetUserTotalUsage(user.id);
        std::wstring totalUsageStr = Utils::FormatBytesW(totalUsage);
        ListView_SetItemText(hUserList_, idx, 8, (LPWSTR)totalUsageStr.c_str());
        
        std::wstring remark = Utils::StringToWString(user.remark);
        ListView_SetItemText(hUserList_, idx, 9, (LPWSTR)remark.c_str());
        
        std::wstring expiry = user.expiryDate.empty() ? L"无限制" : Utils::StringToWString(user.expiryDate);
        ListView_SetItemText(hUserList_, idx, 10, (LPWSTR)expiry.c_str());
        
        std::wstring status = user.enabled ? L"启用" : L"禁用";
        ListView_SetItemText(hUserList_, idx, 11, (LPWSTR)status.c_str());
        
        idx++;
    }
    
    // 自适应列宽
    for (int i = 0; i < 12; i++) {
        ListView_SetColumnWidth(hUserList_, i, LVSCW_AUTOSIZE_USEHEADER);
    }
}

void MainWindow::RefreshPortList() {
    ListView_DeleteAllItems(hPortList_);
    
    auto ports = Database::Instance().GetAllProxyPorts();
    int idx = 0;
    for (const auto& port : ports) {
        LVITEMW lvi = {};
        lvi.mask = LVIF_TEXT;
        lvi.iItem = idx;
        
        std::wstring id = std::to_wstring(port.id);
        lvi.pszText = (LPWSTR)id.c_str();
        ListView_InsertItem(hPortList_, &lvi);
        
        // 监听端口为0时显示"(无)"
        std::wstring listenPort = port.listenPort > 0 ? std::to_wstring(port.listenPort) : L"(无)";
        ListView_SetItemText(hPortList_, idx, 1, (LPWSTR)listenPort.c_str());
        
        std::wstring type = Utils::StringToWString(port.upstreamType);
        ListView_SetItemText(hPortList_, idx, 2, (LPWSTR)type.c_str());
        
        std::wstring host = Utils::StringToWString(port.upstreamHost);
        ListView_SetItemText(hPortList_, idx, 3, (LPWSTR)host.c_str());
        
        std::wstring upPort = std::to_wstring(port.upstreamPort);
        ListView_SetItemText(hPortList_, idx, 4, (LPWSTR)upPort.c_str());
        
        std::wstring desc = Utils::StringToWString(port.description);
        ListView_SetItemText(hPortList_, idx, 5, (LPWSTR)desc.c_str());
        
        std::wstring status = port.enabled ? L"启用" : L"禁用";
        ListView_SetItemText(hPortList_, idx, 6, (LPWSTR)status.c_str());
        
        idx++;
    }
    
    // 自适应列宽
    for (int i = 0; i < 10; i++) {
        ListView_SetColumnWidth(hPortList_, i, LVSCW_AUTOSIZE_USEHEADER);
    }
}

void MainWindow::RefreshTrafficGraph() {
    auto data = TrafficMonitor::Instance().GetCurrentData();
    
    uploadHistory_.push_back(data.uploadSpeed);
    downloadHistory_.push_back(data.downloadSpeed);
    
    while (uploadHistory_.size() > 60) uploadHistory_.erase(uploadHistory_.begin());
    while (downloadHistory_.size() > 60) downloadHistory_.erase(downloadHistory_.begin());
    
    if (currentTab_ == 2) {
        InvalidateRect(hTrafficGraph_, nullptr, FALSE);
        
        // 刷新流量历史列表 - 显示所有用户
        auto users = Database::Instance().GetAllUsers();
        std::string today = Utils::GetCurrentDate();
        
        // 只有当用户数量变化时才重置列表，避免闪烁
        int itemCount = ListView_GetItemCount(hTrafficList_);
        bool needRebuild = (itemCount != (int)users.size());
        
        // 如果数量相同，检查第一个用户名是否匹配以防顺序变化
        if (!needRebuild && itemCount > 0) {
            wchar_t buf[256];
            ListView_GetItemText(hTrafficList_, 0, 0, buf, 256);
            std::wstring firstUsername = Utils::StringToWString(users[0].username);
            if (firstUsername != buf) {
                needRebuild = true;
            }
        }

        if (needRebuild) {
            ListView_DeleteAllItems(hTrafficList_);
            
            // 重新插入所有行
            int idx = 0;
            for (const auto& user : users) {
                LVITEMW lvi = {};
                lvi.mask = LVIF_TEXT;
                lvi.iItem = idx;
                
                std::wstring username = Utils::StringToWString(user.username);
                lvi.pszText = (LPWSTR)username.c_str();
                ListView_InsertItem(hTrafficList_, &lvi);
                idx++;
            }
        }
        
        // 更新每一行的数据 (不再闪烁)
        int idx = 0;
        for (const auto& user : users) {
            std::wstring dateW = Utils::StringToWString(today);
            ListView_SetItemText(hTrafficList_, idx, 1, (LPWSTR)dateW.c_str());
            
            // 获取统计数据
            auto stats = TrafficMonitor::Instance().GetUserStats(user.id);
            
            // 1h
            ListView_SetItemText(hTrafficList_, idx, 2, (LPWSTR)Utils::FormatBytesW(stats.upload1h).c_str());
            ListView_SetItemText(hTrafficList_, idx, 3, (LPWSTR)Utils::FormatBytesW(stats.download1h).c_str());
            
            // 24h
            ListView_SetItemText(hTrafficList_, idx, 4, (LPWSTR)Utils::FormatBytesW(stats.upload24h).c_str());
            ListView_SetItemText(hTrafficList_, idx, 5, (LPWSTR)Utils::FormatBytesW(stats.download24h).c_str());
            
            // 今日 (从数据库获取持久化的+内存未持久化的 session)
            TrafficRecord record;
            int64_t uploadBytes = 0, downloadBytes = 0;
            if (Database::Instance().GetDailyTraffic(user.id, today, record)) {
                uploadBytes = record.uploadBytes;
                downloadBytes = record.downloadBytes;
            }
            
            ListView_SetItemText(hTrafficList_, idx, 6, (LPWSTR)Utils::FormatBytesW(uploadBytes).c_str());
            ListView_SetItemText(hTrafficList_, idx, 7, (LPWSTR)Utils::FormatBytesW(downloadBytes).c_str());
            
            // 本周
            ListView_SetItemText(hTrafficList_, idx, 8, (LPWSTR)Utils::FormatBytesW(stats.uploadWeek).c_str());
            ListView_SetItemText(hTrafficList_, idx, 9, (LPWSTR)Utils::FormatBytesW(stats.downloadWeek).c_str());
            
            // 本月
            ListView_SetItemText(hTrafficList_, idx, 10, (LPWSTR)Utils::FormatBytesW(stats.uploadMonth).c_str());
            ListView_SetItemText(hTrafficList_, idx, 11, (LPWSTR)Utils::FormatBytesW(stats.downloadMonth).c_str());
            
            idx++;
        }
    }
}

void MainWindow::DrawTrafficGraph(HDC hdc, RECT& rect) {
    // 使用GDI+绘制平滑曲线
    Graphics graphics(hdc);
    graphics.SetSmoothingMode(SmoothingModeAntiAlias);
    
    // 背景
    SolidBrush bgBrush(Gdiplus::Color(255, 49, 50, 68));
    graphics.FillRectangle(&bgBrush, rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top);
    
    int width = rect.right - rect.left;
    int height = rect.bottom - rect.top;
    int padding = 40;
    int graphWidth = width - padding * 2;
    int graphHeight = height - padding * 2;
    
    // 绘制网格
    Pen gridPen(Gdiplus::Color(50, 205, 214, 244), 1);
    for (int i = 0; i <= 4; i++) {
        int y = padding + graphHeight * i / 4;
        graphics.DrawLine(&gridPen, padding, y, width - padding, y);
    }
    
    if (uploadHistory_.empty()) return;
    
    // 找最大值
    int64_t maxSpeed = 1024;
    for (auto v : uploadHistory_) if (v > maxSpeed) maxSpeed = v;
    for (auto v : downloadHistory_) if (v > maxSpeed) maxSpeed = v;
    maxSpeed = (maxSpeed / 1024 + 1) * 1024; // 向上取整到KB
    
    // 绘制上传曲线
    std::vector<PointF> uploadPoints;
    for (size_t i = 0; i < uploadHistory_.size(); i++) {
        float x = (float)(padding + graphWidth * i / 60);
        float y = (float)(padding + graphHeight - graphHeight * uploadHistory_[i] / maxSpeed);
        uploadPoints.push_back(PointF(x, y));
    }
    
    if (uploadPoints.size() > 1) {
        Pen uploadPen(Gdiplus::Color(255, 250, 179, 135), 2);
        graphics.DrawCurve(&uploadPen, uploadPoints.data(), (int)uploadPoints.size());
    }
    
    // 绘制下载曲线
    std::vector<PointF> downloadPoints;
    for (size_t i = 0; i < downloadHistory_.size(); i++) {
        float x = (float)(padding + graphWidth * i / 60);
        float y = (float)(padding + graphHeight - graphHeight * downloadHistory_[i] / maxSpeed);
        downloadPoints.push_back(PointF(x, y));
    }
    
    if (downloadPoints.size() > 1) {
        Pen downloadPen(Gdiplus::Color(255, 148, 226, 213), 2);
        graphics.DrawCurve(&downloadPen, downloadPoints.data(), (int)downloadPoints.size());
    }
    
    // 图例
    SolidBrush textBrush(Gdiplus::Color(255, 205, 214, 244));
    FontFamily fontFamily(L"Microsoft YaHei UI");
    Gdiplus::Font font(&fontFamily, 12, FontStyleRegular, UnitPixel);
    
    auto traffic = TrafficMonitor::Instance().GetCurrentData();
    std::wstring uploadStr = L"↑ 上传: " + Utils::FormatBytesW(traffic.uploadSpeed) + L"/s";
    std::wstring downloadStr = L"↓ 下载: " + Utils::FormatBytesW(traffic.downloadSpeed) + L"/s";
    
    SolidBrush uploadBrush(Gdiplus::Color(255, 250, 179, 135));
    SolidBrush downloadBrush(Gdiplus::Color(255, 148, 226, 213));
    
    graphics.DrawString(uploadStr.c_str(), -1, &font, PointF((float)padding, 10), &uploadBrush);
    graphics.DrawString(downloadStr.c_str(), -1, &font, PointF((float)(width / 2), 10), &downloadBrush);
    
    // Y轴刻度
    for (int i = 0; i <= 4; i++) {
        int64_t value = maxSpeed * (4 - i) / 4;
        std::wstring label = Utils::FormatBytesW(value) + L"/s";
        graphics.DrawString(label.c_str(), -1, &font, PointF(5, (float)(padding + graphHeight * i / 4 - 8)), &textBrush);
    }
}

void MainWindow::CreateLogPage() {
    HFONT hFont = CreateFontW(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei UI");
    
    // 获取Tab内容区域相对于主窗口的位置
    RECT tabClientRect;
    GetWindowRect(hTab_, &tabClientRect);
    MapWindowPoints(HWND_DESKTOP, hwnd_, (LPPOINT)&tabClientRect, 2);
    
    RECT tabRect;
    GetClientRect(hTab_, &tabRect);
    TabCtrl_AdjustRect(hTab_, FALSE, &tabRect);
    
    // 转换为相对于主窗口的坐标
    int left = tabClientRect.left + tabRect.left + 10;
    int top = tabClientRect.top + tabRect.top + 5;
    int width = tabRect.right - tabRect.left - 20;
    int height = tabRect.bottom - tabRect.top - 15;
    
    // 日志列表
    hLogList_ = CreateWindowExW(0, WC_LISTVIEWW, L"",
        WS_CHILD | LVS_REPORT | LVS_SINGLESEL | WS_BORDER,
        left, top, width, height,
        hwnd_, (HMENU)IDC_LIST_LOGS, hInstance_, nullptr);
    SendMessage(hLogList_, WM_SETFONT, (WPARAM)hFont, TRUE);
    ListView_SetExtendedListViewStyle(hLogList_, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
    ListView_SetBkColor(hLogList_, COLOR_SURFACE);
    ListView_SetTextBkColor(hLogList_, COLOR_SURFACE);
    ListView_SetTextColor(hLogList_, COLOR_TEXT);
    SetWindowTheme(hLogList_, L"", L"");
    
    // 列
    LVCOLUMNW lvc = {};
    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT;
    lvc.fmt = LVCFMT_LEFT;
    
    lvc.cx = 160;
    lvc.pszText = (LPWSTR)L"时间";
    ListView_InsertColumn(hLogList_, 0, &lvc);
    
    lvc.cx = 100;
    lvc.pszText = (LPWSTR)L"用户名";
    ListView_InsertColumn(hLogList_, 1, &lvc);
    
    lvc.cx = 120;
    lvc.pszText = (LPWSTR)L"代理";
    ListView_InsertColumn(hLogList_, 2, &lvc);

    lvc.cx = 130;
    lvc.pszText = (LPWSTR)L"客户端IP";
    ListView_InsertColumn(hLogList_, 3, &lvc);
    
    lvc.cx = 300;
    lvc.pszText = (LPWSTR)L"目标地址";
    ListView_InsertColumn(hLogList_, 4, &lvc);
    
    lvc.cx = 100;
    lvc.pszText = (LPWSTR)L"操作";
    ListView_InsertColumn(hLogList_, 5, &lvc);
    
    ShowWindow(hLogList_, SW_HIDE);
    
    // 设置日志回调 - 使用PostMessage而不是直接调用
    ConnectionLogger::Instance().SetUICallback([this](const ConnectionLogEntry& entry) {
        // 创建条目的副本并通过消息发送
        auto entryCopy = new ConnectionLogEntry(entry);
        PostMessage(hwnd_, WM_ADD_LOG_ENTRY, 0, (LPARAM)entryCopy);
    });
}

void MainWindow::RefreshLogList() {
    ListView_DeleteAllItems(hLogList_);
    
    auto logs = ConnectionLogger::Instance().GetRecentLogs(100);  // 仅保留最近100条
    
    // 按时间倒序显示（最新的在前）
    for (auto it = logs.rbegin(); it != logs.rend(); ++it) {
        const auto& entry = *it;
        
        LVITEMW lvi = {};
        lvi.mask = LVIF_TEXT;
        lvi.iItem = ListView_GetItemCount(hLogList_);
        
        std::wstring ts = Utils::StringToWString(entry.timestamp);
        lvi.pszText = (LPWSTR)ts.c_str();
        int idx = ListView_InsertItem(hLogList_, &lvi);
        
        std::wstring user = Utils::StringToWString(entry.username);
        ListView_SetItemText(hLogList_, idx, 1, (LPWSTR)user.c_str());
        
        std::wstring proxy = Utils::StringToWString(entry.proxyDesc);
        ListView_SetItemText(hLogList_, idx, 2, (LPWSTR)proxy.c_str());

        std::wstring ip = Utils::StringToWString(entry.clientIP);
        ListView_SetItemText(hLogList_, idx, 3, (LPWSTR)ip.c_str());
        
        std::wstring target = Utils::StringToWString(entry.targetHost + ":" + std::to_string(entry.targetPort));
        ListView_SetItemText(hLogList_, idx, 4, (LPWSTR)target.c_str());
        
        std::wstring action = Utils::StringToWString(entry.action);
        ListView_SetItemText(hLogList_, idx, 5, (LPWSTR)action.c_str());
    }
}

void MainWindow::ClearLogs() {
    ListView_DeleteAllItems(hLogList_);
}

void MainWindow::AddLogEntry(const ConnectionLogEntry& entry) {
    // 这个函数通过WM_ADD_LOG_ENTRY消息处理
}

void MainWindow::CreateTrayIcon() {
    if (trayIconCreated_) return;
    
    ZeroMemory(&nid_, sizeof(nid_));
    nid_.cbSize = sizeof(nid_);
    nid_.hWnd = hwnd_;
    nid_.uID = 1;
    nid_.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    nid_.uCallbackMessage = WM_TRAYICON;
    nid_.hIcon = (HICON)LoadImageW(hInstance_, MAKEINTRESOURCEW(1), IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR);
    if (!nid_.hIcon) nid_.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
    wcscpy_s(nid_.szTip, L"ProxyRelay - 二级代理管理器");
    
    Shell_NotifyIconW(NIM_ADD, &nid_);
    trayIconCreated_ = true;
}

void MainWindow::RemoveTrayIcon() {
    if (!trayIconCreated_) return;
    Shell_NotifyIconW(NIM_DELETE, &nid_);
    trayIconCreated_ = false;
}

void MainWindow::ShowTrayMenu() {
    POINT pt;
    GetCursorPos(&pt);
    
    HMENU hMenu = CreatePopupMenu();
    AppendMenuW(hMenu, MF_STRING, ID_TRAY_SHOW, L"显示窗口");
    AppendMenuW(hMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hMenu, MF_STRING | (IsAutoStartEnabled() ? MF_CHECKED : 0), ID_TRAY_AUTOSTART, L"开机自启");
    AppendMenuW(hMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hMenu, MF_STRING, ID_TRAY_EXIT, L"退出程序");
    
    SetForegroundWindow(hwnd_);
    UINT cmd = TrackPopupMenu(hMenu, TPM_RETURNCMD | TPM_NONOTIFY, pt.x, pt.y, 0, hwnd_, nullptr);
    DestroyMenu(hMenu);
    
    switch (cmd) {
    case ID_TRAY_SHOW:
        RestoreFromTray();
        break;
    case ID_TRAY_AUTOSTART:
        SetAutoStart(!IsAutoStartEnabled());
        break;
    case ID_TRAY_EXIT:
        RemoveTrayIcon();
        DestroyWindow(hwnd_);
        break;
    }
}

void MainWindow::MinimizeToTray() {
    ShowWindow(hwnd_, SW_HIDE);
}

void MainWindow::RestoreFromTray() {
    ShowWindow(hwnd_, SW_SHOW);
    ShowWindow(hwnd_, SW_RESTORE);
    SetForegroundWindow(hwnd_);
}

bool MainWindow::IsAutoStartEnabled() {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 
                      0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return false;
    }
    
    wchar_t path[MAX_PATH];
    DWORD size = sizeof(path);
    DWORD type;
    bool exists = RegQueryValueExW(hKey, L"ProxyRelay", nullptr, &type, (LPBYTE)path, &size) == ERROR_SUCCESS;
    RegCloseKey(hKey);
    return exists;
}

void MainWindow::SetAutoStart(bool enable) {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 
                      0, KEY_WRITE, &hKey) != ERROR_SUCCESS) {
        MessageBoxW(hwnd_, L"无法访问注册表", L"错误", MB_OK | MB_ICONERROR);
        return;
    }
    
    if (enable) {
        wchar_t exePath[MAX_PATH];
        GetModuleFileNameW(nullptr, exePath, MAX_PATH);
        RegSetValueExW(hKey, L"ProxyRelay", 0, REG_SZ, (LPBYTE)exePath, (DWORD)((wcslen(exePath) + 1) * sizeof(wchar_t)));
    } else {
        RegDeleteValueW(hKey, L"ProxyRelay");
    }
    
    RegCloseKey(hKey);
}

void MainWindow::ToggleSelectedUser() {
    int sel = ListView_GetNextItem(hUserList_, -1, LVNI_SELECTED);
    if (sel < 0) return;
    
    wchar_t buffer[32];
    ListView_GetItemText(hUserList_, sel, 0, buffer, 32);
    int userId = _wtoi(buffer);
    
    UserInfo user;
    if (Database::Instance().GetUser(userId, user)) {
        user.enabled = !user.enabled;
        Database::Instance().UpdateUser(user);
        RefreshUserList();
    }
}

void MainWindow::ToggleSelectedPort() {
    int sel = ListView_GetNextItem(hPortList_, -1, LVNI_SELECTED);
    if (sel < 0) return;
    
    wchar_t buffer[32];
    ListView_GetItemText(hPortList_, sel, 0, buffer, 32);
    int portId = _wtoi(buffer);
    
    ProxyPort port;
    if (Database::Instance().GetProxyPort(portId, port)) {
        port.enabled = !port.enabled;
        Database::Instance().UpdateProxyPort(port);
        RefreshPortList();
        ProxyServer::Instance().ReloadPorts();
    }
}

void MainWindow::UpdatePortStats() {
    int count = ListView_GetItemCount(hPortList_);
    wchar_t buffer[32];
    
    for (int i = 0; i < count; i++) {
        ListView_GetItemText(hPortList_, i, 0, buffer, 32);
        int portId = _wtoi(buffer);
        
        auto stats = TrafficMonitor::Instance().GetPortStats(portId);
        
        // 实时速度
        std::wstring speed = L"↑" + Utils::FormatBytesW(stats.uploadSpeed) + 
                             L"/s ↓" + Utils::FormatBytesW(stats.downloadSpeed) + L"/s";
        ListView_SetItemText(hPortList_, i, 7, (LPWSTR)speed.c_str());
        
        // 1h
        std::wstring total1h = L"↑" + Utils::FormatBytesW(stats.upload1h) + 
                               L" ↓" + Utils::FormatBytesW(stats.download1h);
        ListView_SetItemText(hPortList_, i, 8, (LPWSTR)total1h.c_str());
        
        // 24h
        std::wstring total24h = L"↑" + Utils::FormatBytesW(stats.upload24h) + 
                                L" ↓" + Utils::FormatBytesW(stats.download24h);
        ListView_SetItemText(hPortList_, i, 9, (LPWSTR)total24h.c_str());
        
        // 本周
        std::wstring totalWeek = L"↑" + Utils::FormatBytesW(stats.uploadWeek) + 
                                 L" ↓" + Utils::FormatBytesW(stats.downloadWeek);
        ListView_SetItemText(hPortList_, i, 10, (LPWSTR)totalWeek.c_str());
        
        // 本月
        std::wstring totalMonth = L"↑" + Utils::FormatBytesW(stats.uploadMonth) + 
                                  L" ↓" + Utils::FormatBytesW(stats.downloadMonth);
        ListView_SetItemText(hPortList_, i, 11, (LPWSTR)totalMonth.c_str());
        
        // 上月
        std::wstring lastMonth = L"↑" + Utils::FormatBytesW(stats.uploadLastMonth) + 
                                 L" ↓" + Utils::FormatBytesW(stats.downloadLastMonth);
        ListView_SetItemText(hPortList_, i, 12, (LPWSTR)lastMonth.c_str());
    }
}


// New Ban Management Page
void MainWindow::CreateBanPage() {
    RECT tabClientRect;
    GetWindowRect(hTab_, &tabClientRect);
    MapWindowPoints(HWND_DESKTOP, hwnd_, (LPPOINT)&tabClientRect, 2);
    
    RECT tabRect;
    GetClientRect(hTab_, &tabRect);
    TabCtrl_AdjustRect(hTab_, FALSE, &tabRect);
    
    int left = tabClientRect.left + tabRect.left + 10;
    int top = tabClientRect.top + tabRect.top + 5;
    int width = tabRect.right - tabRect.left - 20;
    int settingsHeight = 40;
    int listHeight = tabRect.bottom - tabRect.top - settingsHeight - 50; 
    int settingsTop = tabClientRect.top + tabRect.bottom - settingsHeight - 10;
    
    HFONT hFont = CreateFontW(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei UI");

    // Ban Type Combo
    hBanTypeCombo_ = CreateWindowW(WC_COMBOBOXW, L"", 
        WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST,
        left, top, 150, 200, hwnd_, (HMENU)IDC_COMBO_BAN_TYPE, hInstance_, NULL);
    SendMessage(hBanTypeCombo_, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(hBanTypeCombo_, CB_ADDSTRING, 0, (LPARAM)L"白名单 (Whitelist)");
    SendMessage(hBanTypeCombo_, CB_ADDSTRING, 0, (LPARAM)L"黑名单 (Blacklist)");
    SendMessage(hBanTypeCombo_, CB_ADDSTRING, 0, (LPARAM)L"自动封禁 (Auto-Ban)");
    SendMessage(hBanTypeCombo_, CB_ADDSTRING, 0, (LPARAM)L"免认证 (No-Auth IP)");
    SendMessage(hBanTypeCombo_, CB_SETCURSEL, 0, 0);
    Utils::SetToolTip(hToolTip_, hBanTypeCombo_, L"选择不同的封禁和认证策略类型进行管理。");

    // Buttons
    HWND hBtnAdd = CreateWindowW(L"BUTTON", L"添加ID/IP",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        left + 160, top, 100, 25, hwnd_, (HMENU)IDC_BTN_ADD_BAN, hInstance_, nullptr);
    SendMessage(hBtnAdd, WM_SETFONT, (WPARAM)hFont, TRUE);
    Utils::SetToolTip(hToolTip_, hBtnAdd, L"向当前策略列表中添加新的规则（IP或CIDR）");

    HWND hBtnDel = CreateWindowW(L"BUTTON", L"删除/解封",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        left + 270, top, 100, 25, hwnd_, (HMENU)IDC_BTN_DEL_BAN, hInstance_, nullptr);
    SendMessage(hBtnDel, WM_SETFONT, (WPARAM)hFont, TRUE);
    Utils::SetToolTip(hToolTip_, hBtnDel, L"将选中项从列表中删除。如果是自动封禁的IP，则提前解封。");

    // List View
    hBanList_ = CreateWindowExW(0, WC_LISTVIEWW, L"",
        WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | WS_BORDER,
        left, top + 30, width, listHeight,
        hwnd_, (HMENU)IDC_LIST_BAN, hInstance_, nullptr);
    ListView_SetExtendedListViewStyle(hBanList_, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
    SendMessage(hBanList_, WM_SETFONT, (WPARAM)hFont, TRUE);
    
    LVCOLUMNW lvc = {};
    lvc.mask = LVCF_TEXT | LVCF_WIDTH;
    lvc.pszText = (LPWSTR)L"ID"; lvc.cx = 50;
    ListView_InsertColumn(hBanList_, 0, &lvc);
    lvc.pszText = (LPWSTR)L"IP地址"; lvc.cx = 150;
    ListView_InsertColumn(hBanList_, 1, &lvc);
    lvc.pszText = (LPWSTR)L"备注/过期时间"; lvc.cx = 250;
    ListView_InsertColumn(hBanList_, 2, &lvc);
    lvc.pszText = (LPWSTR)L"创建时间"; lvc.cx = 150;
    ListView_InsertColumn(hBanList_, 3, &lvc);

    // Settings Area (M, N, T)
    int y = settingsTop;
    
    HWND hLbl = CreateWindowW(L"STATIC", L"策略: 在", WS_CHILD | WS_VISIBLE, left, y+3, 60, 20, hwnd_, (HMENU)IDC_STATIC_BAN_N, hInstance_, NULL);
    SendMessage(hLbl, WM_SETFONT, (WPARAM)hFont, TRUE);
    // Set transparent background for static controls usually handled in WM_CTLCOLORSTATIC/WM_CTLCOLORBTN
    
    HWND hEditN = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"5", WS_CHILD | WS_VISIBLE | ES_NUMBER | ES_CENTER, left + 60, y, 40, 25, hwnd_, (HMENU)IDC_EDIT_N, hInstance_, NULL);
    SendMessage(hEditN, WM_SETFONT, (WPARAM)hFont, TRUE);
    Utils::SetToolTip(hToolTip_, hEditN, L"连续错误登录的检测时间窗口（N 分钟）");
    
    hLbl = CreateWindowW(L"STATIC", L"分钟内，错误", WS_CHILD | WS_VISIBLE, left + 105, y+3, 90, 20, hwnd_, (HMENU)IDC_STATIC_BAN_M, hInstance_, NULL);
    SendMessage(hLbl, WM_SETFONT, (WPARAM)hFont, TRUE);
    
    HWND hEditM = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"5", WS_CHILD | WS_VISIBLE | ES_NUMBER | ES_CENTER, left + 195, y, 40, 25, hwnd_, (HMENU)IDC_EDIT_M, hInstance_, NULL);
    SendMessage(hEditM, WM_SETFONT, (WPARAM)hFont, TRUE);
    Utils::SetToolTip(hToolTip_, hEditM, L"触发封禁所需的错误次数（M 次）");
    
    hLbl = CreateWindowW(L"STATIC", L"次，封禁IP", WS_CHILD | WS_VISIBLE, left + 240, y+3, 70, 20, hwnd_, (HMENU)IDC_STATIC_BAN_T, hInstance_, NULL);
    SendMessage(hLbl, WM_SETFONT, (WPARAM)hFont, TRUE);
    
    HWND hEditT = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"60", WS_CHILD | WS_VISIBLE | ES_NUMBER | ES_CENTER, left + 310, y, 50, 25, hwnd_, (HMENU)IDC_EDIT_T, hInstance_, NULL);
    SendMessage(hEditT, WM_SETFONT, (WPARAM)hFont, TRUE);
    Utils::SetToolTip(hToolTip_, hEditT, L"封禁该IP的持续时间（T 分钟），过期后自动恢复访问");
    
    hLbl = CreateWindowW(L"STATIC", L"分钟", WS_CHILD | WS_VISIBLE, left + 365, y+3, 40, 20, hwnd_, (HMENU)IDC_STATIC_BAN_MINUTES, hInstance_, NULL);
    SendMessage(hLbl, WM_SETFONT, (WPARAM)hFont, TRUE);
    
    HWND hBtnSave = CreateWindowW(L"BUTTON", L"保存设置", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, left + 410, y, 80, 25, hwnd_, (HMENU)IDC_BTN_SAVE_BAN_SETTINGS, hInstance_, NULL);
    SendMessage(hBtnSave, WM_SETFONT, (WPARAM)hFont, TRUE);
    Utils::SetToolTip(hToolTip_, hBtnSave, L"保存自动封禁设定的参数");

    // Initial Values
    SetWindowTextA(hEditN, Database::Instance().GetConfig("login_fail_window", "5").c_str());
    SetWindowTextA(hEditM, Database::Instance().GetConfig("login_fail_limit", "5").c_str());
    SetWindowTextA(hEditT, Database::Instance().GetConfig("ban_duration", "60").c_str());
    
    RefreshBanList();
}

void MainWindow::RefreshBanList() {
    ListView_DeleteAllItems(hBanList_);
    currentBanType_ = SendMessage(hBanTypeCombo_, CB_GETCURSEL, 0, 0);
    
    std::vector<Database::BanInfo> list;
    if (currentBanType_ == 0) list = Database::Instance().GetWhitelist();
    else if (currentBanType_ == 1) list = Database::Instance().GetBlacklist();
    else if (currentBanType_ == 2) list = Database::Instance().GetAutoBanList();
    else if (currentBanType_ == 3) list = Database::Instance().GetNoAuthList();
    
    for (const auto& item : list) {
        std::wstring id = std::to_wstring(item.id);
        std::wstring ip = Utils::StringToWString(item.ip);
        std::wstring remark;
        if (currentBanType_ == 2) {
             time_t expiry = (time_t)item.expiryTime;
             // checkout if expired
             if (expiry < time(nullptr)) remark = L"已过期";
             else {
                 char buf[64];
                 tm tm;
                 localtime_s(&tm, &expiry); // Windows safe version
                 strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);
                 remark = Utils::StringToWString(buf);
             }
        } else {
            remark = Utils::StringToWString(item.remark);
        }
        std::wstring created = Utils::StringToWString(item.createdAt);
        
        LVITEMW lvi = {};
        lvi.mask = LVIF_TEXT;
        lvi.iItem = ListView_GetItemCount(hBanList_);
        lvi.pszText = (LPWSTR)id.c_str();
        int idx = ListView_InsertItem(hBanList_, &lvi);
        
        ListView_SetItemText(hBanList_, idx, 1, (LPWSTR)ip.c_str());
        ListView_SetItemText(hBanList_, idx, 2, (LPWSTR)remark.c_str());
        ListView_SetItemText(hBanList_, idx, 3, (LPWSTR)created.c_str());
    }
}

void MainWindow::OnBanTypeChanged() {
    RefreshBanList();
    // Enable/Disable Add button for AutoBan
    HWND hBtnAdd = GetDlgItem(hwnd_, IDC_BTN_ADD_BAN);
    EnableWindow(hBtnAdd, currentBanType_ != 2);
}

void MainWindow::DeleteSelectedBan() {
    int sel = ListView_GetNextItem(hBanList_, -1, LVNI_SELECTED);
    if (sel < 0) return;
    
    wchar_t buffer[32];
    ListView_GetItemText(hBanList_, sel, 0, buffer, 32);
    int id = _wtoi(buffer);
    
    currentBanType_ = SendMessage(hBanTypeCombo_, CB_GETCURSEL, 0, 0);
    
    if (MessageBoxW(hwnd_, L"确定要删除/解封此条目吗?", L"确认", MB_YESNO | MB_ICONQUESTION) == IDYES) {
        bool success = false;
        if (currentBanType_ == 0) success = Database::Instance().RemoveFromWhitelist(id);
        else if (currentBanType_ == 1) success = Database::Instance().RemoveFromBlacklist(id);
        else if (currentBanType_ == 2) success = Database::Instance().RemoveFromAutoBan(id);
        else if (currentBanType_ == 3) success = Database::Instance().RemoveFromNoAuthList(id);
        
        if (success) {
            RefreshBanList();
        }
    }
}

void MainWindow::SaveBanSettings() {
    char buf[32];
    GetWindowTextA(GetDlgItem(hwnd_, IDC_EDIT_N), buf, 32);
    Database::Instance().SetConfig("login_fail_window", buf);
    
    GetWindowTextA(GetDlgItem(hwnd_, IDC_EDIT_M), buf, 32);
    Database::Instance().SetConfig("login_fail_limit", buf);
    
    GetWindowTextA(GetDlgItem(hwnd_, IDC_EDIT_T), buf, 32);
    Database::Instance().SetConfig("ban_duration", buf);
    
    MessageBoxW(hwnd_, L"设置已保存", L"提示", MB_OK);
}

void MainWindow::CreateBypassPage() {
    RECT tabClientRect;
    GetWindowRect(hTab_, &tabClientRect);
    MapWindowPoints(HWND_DESKTOP, hwnd_, (LPPOINT)&tabClientRect, 2);
    
    RECT tabRect;
    GetClientRect(hTab_, &tabRect);
    TabCtrl_AdjustRect(hTab_, FALSE, &tabRect);
    
    int left = tabClientRect.left + tabRect.left + 10;
    int top = tabClientRect.top + tabRect.top + 5;
    int width = tabRect.right - tabRect.left - 20;
    int totalHeight = tabRect.bottom - tabRect.top - 15;
    int btnTop = tabClientRect.top + tabRect.bottom - 40;
    
    HFONT hFont = CreateFontW(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei UI");

    int y = top;
    
    // 标题
    HWND hTitle = CreateWindowExW(0, L"STATIC", L"路由规则 (为每个代理配置自定义路由规则，支持 IP/CIDR 和域名，空格或换行分隔):", 
        WS_CHILD | WS_VISIBLE, left, y, width, 20, hwnd_, (HMENU)10020, hInstance_, NULL);
    SendMessage(hTitle, WM_SETFONT, (WPARAM)hFont, TRUE);
    SetWindowTheme(hTitle, L"", L"");
    y += 25;
    
    // 获取代理配置列表
    auto proxies = Database::Instance().GetAllProxyPorts();
    int proxyCount = (int)proxies.size();
    
    // 计算每个编辑框的高度
    int availableHeight = btnTop - y - 45;  // 留出底部按钮空间
    int editCount = 1 + proxyCount;  // 直连 + 各代理
    int labelHeight = 20;
    int editHeight = (availableHeight - editCount * (labelHeight + 5)) / editCount;
    if (editHeight < 50) editHeight = 50;  // 最小高度
    if (editHeight > 120) editHeight = 120;  // 最大高度
    
    // 清除旧的控件
    routingRuleEdits_.clear();
    
    // 创建直连规则编辑框
    {
        RoutingRuleEdit edit;
        edit.proxyId = 0;
        edit.label = L"直连规则 (匹配这些地址将直接连接，不走代理):";
        edit.hPriorityLabel = nullptr;  // 直连规则没有优先级
        edit.hPriorityEdit = nullptr;
        
        edit.hLabel = CreateWindowExW(0, L"STATIC", edit.label.c_str(), 
            WS_CHILD | WS_VISIBLE, left, y, width, labelHeight, hwnd_, (HMENU)(13000), hInstance_, NULL);
        SendMessage(edit.hLabel, WM_SETFONT, (WPARAM)hFont, TRUE);
        SetWindowTheme(edit.hLabel, L"", L"");
        y += labelHeight + 2;
        
        edit.hEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", 
            WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL | WS_VSCROLL, 
            left, y, width, editHeight, hwnd_, (HMENU)(13100), hInstance_, NULL);
        SendMessage(edit.hEdit, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessage(edit.hEdit, EM_SETLIMITTEXT, 1000000, 0);  // 支持1MB字符，约10000+条规则
        SetWindowTheme(edit.hEdit, L"", L"");
        Utils::SetToolTip(hToolTip_, edit.hEdit, L"设置强制直连（不走代理）的目标IP或域名规则，每行一个。例如：192.168.1.0/24");
        y += editHeight + 5;
        
        routingRuleEdits_.push_back(edit);
    }
    
    // 为每个代理创建规则编辑框
    for (int i = 0; i < proxyCount; i++) {
        const auto& proxy = proxies[i];
        RoutingRuleEdit edit;
        edit.proxyId = proxy.id;
        
        std::wstring proxyName = Utils::StringToWString(
            proxy.description.empty() ? 
            (proxy.upstreamType + "://" + proxy.upstreamHost + ":" + std::to_string(proxy.upstreamPort)) : 
            proxy.description);
        edit.label = L"代理 " + std::to_wstring(proxy.id) + L": " + proxyName + L" 规则:";
        
        // 优先级标签和输入框（在一行）
        edit.hPriorityLabel = CreateWindowExW(0, L"STATIC", L"优先级:", 
            WS_CHILD | WS_VISIBLE, left, y, 50, labelHeight, hwnd_, 
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(14000 + i + 1)), hInstance_, NULL);
        SendMessage(edit.hPriorityLabel, WM_SETFONT, (WPARAM)hFont, TRUE);
        SetWindowTheme(edit.hPriorityLabel, L"", L"");
        
        edit.hPriorityEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", std::to_wstring(i + 1).c_str(),
            WS_CHILD | WS_VISIBLE | ES_NUMBER, left + 55, y, 40, labelHeight + 4, hwnd_, 
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(14100 + i + 1)), hInstance_, NULL);
        SendMessage(edit.hPriorityEdit, WM_SETFONT, (WPARAM)hFont, TRUE);
        SetWindowTheme(edit.hPriorityEdit, L"", L"");
        
        // 规则标签
        edit.hLabel = CreateWindowExW(0, L"STATIC", edit.label.c_str(), 
            WS_CHILD | WS_VISIBLE, left + 105, y, width - 105, labelHeight, hwnd_, 
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(13000 + i + 1)), hInstance_, NULL);
        SendMessage(edit.hLabel, WM_SETFONT, (WPARAM)hFont, TRUE);
        SetWindowTheme(edit.hLabel, L"", L"");
        y += labelHeight + 2;
        
        edit.hEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", 
            WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL | WS_VSCROLL, 
            left, y, width, editHeight, hwnd_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(13100 + i + 1)), hInstance_, NULL);
        SendMessage(edit.hEdit, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessage(edit.hEdit, EM_SETLIMITTEXT, 1000000, 0);  // 支持1MB字符，约10000+条规则
        SetWindowTheme(edit.hEdit, L"", L"");
        Utils::SetToolTip(hToolTip_, edit.hEdit, L"配置应通过此代理端口转发的流量规则，每行一个。例如：10.0.0.0/8 或 google.com");
        y += editHeight + 5;
        
        routingRuleEdits_.push_back(edit);
    }
    
    // 保存按钮
    HWND hBtn1 = CreateWindowExW(0, L"BUTTON", L"保存路由规则", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 
        left, btnTop, 120, 30, hwnd_, (HMENU)IDC_BTN_SAVE_BYPASS, hInstance_, NULL);
    SendMessage(hBtn1, WM_SETFONT, (WPARAM)hFont, TRUE);
    SetWindowTheme(hBtn1, L"", L"");
    Utils::SetToolTip(hToolTip_, hBtn1, L"保存配置的自定义流量分发路由网络规则");
    
    // 加载已保存的路由规则
    LoadAllRoutingRules();
}

void MainWindow::SaveBypassConfig() {
    SaveAllRoutingRules();
}

void MainWindow::SaveAllRoutingRules() {
    // 首先删除旧的路由规则
    auto oldRules = Database::Instance().GetAllRoutingRules();
    for (const auto& rule : oldRules) {
        Database::Instance().DeleteRoutingRule(rule.id);
    }
    
    // 为每个编辑框创建新规则
    for (const auto& edit : routingRuleEdits_) {
        // 获取编辑框文本长度
        LRESULT lenResult = SendMessage(edit.hEdit, WM_GETTEXTLENGTH, 0, 0);
        if (lenResult == 0) continue;  // 空的跳过
        
        size_t len = static_cast<size_t>(lenResult);
        
        // 使用 vector 作为缓冲区，确保足够大
        std::vector<char> buffer(len + 2, '\0');
        SendMessageA(edit.hEdit, WM_GETTEXT, buffer.size(), (LPARAM)buffer.data());
        
        std::string text(buffer.data());
        
        // 获取优先级（代理规则才有，直连规则优先级固定为 999，即最低）
        int priority = 999;  // 直连规则优先级最低
        if (edit.proxyId > 0 && edit.hPriorityEdit) {
            wchar_t prioText[16] = {0};
            GetWindowTextW(edit.hPriorityEdit, prioText, 16);
            priority = _wtoi(prioText);
            if (priority <= 0) priority = 1;
        }
        
        // 创建规则
        RoutingRule rule;
        rule.proxyId = edit.proxyId;
        rule.enabled = true;
        rule.priority = priority;
        
        // 简化实现：将所有规则都作为 "mixed" 类型存储
        rule.matchType = "mixed";  // 混合类型，同时匹配 IP/CIDR 和域名
        rule.matchValue = text;
        rule.description = edit.proxyId == 0 ? "Direct rules" : "Proxy " + std::to_string(edit.proxyId) + " rules";
        
        Database::Instance().AddRoutingRule(rule);
    }
    
    // 重新加载规则到内存
    RuleManager::Instance().ReloadRoutingRules();
    
    MessageBoxW(hwnd_, L"路由规则已保存并立即生效", L"提示", MB_OK);
}

void MainWindow::LoadAllRoutingRules() {
    auto dbRules = Database::Instance().GetAllRoutingRules();
    
    for (auto& edit : routingRuleEdits_) {
        // 查找对应 proxyId 的规则
        std::string matchValue;
        int priority = 1;
        for (const auto& rule : dbRules) {
            if (rule.proxyId == edit.proxyId) {
                matchValue = rule.matchValue;
                priority = rule.priority;
                break;
            }
        }
        
        // 使用 WM_SETTEXT 消息设置文本
        SendMessageA(edit.hEdit, WM_SETTEXT, 0, (LPARAM)matchValue.c_str());
        
        // 设置优先级（代理规则才有）
        if (edit.proxyId > 0 && edit.hPriorityEdit) {
            SetWindowTextW(edit.hPriorityEdit, std::to_wstring(priority).c_str());
        }
    }
}

void MainWindow::UpdateRules() {
    RuleManager::Instance().TriggerUpdate();
    MessageBoxW(hwnd_, L"已触发后台更新，完成后将自动加载。", L"提示", MB_OK);
}

void MainWindow::CreateSettingsPage() {
    RECT tabClientRect;
    GetWindowRect(hTab_, &tabClientRect);
    MapWindowPoints(HWND_DESKTOP, hwnd_, (LPPOINT)&tabClientRect, 2);
    
    RECT tabRect;
    GetClientRect(hTab_, &tabRect);
    TabCtrl_AdjustRect(hTab_, FALSE, &tabRect);
    
    int left = tabClientRect.left + tabRect.left + 10;
    int top = tabClientRect.top + tabRect.top + 5;
    int width = tabRect.right - tabRect.left - 20;
    int totalHeight = tabRect.bottom - tabRect.top - 50;
    int btnTop = tabClientRect.top + tabRect.bottom - 40;
    
    HFONT hFont = CreateFontW(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei UI");

    int y = top;
    
    // 自动代理端口（可选，空或0表示关闭）
    HWND hLbl1 = CreateWindowExW(0, L"STATIC", L"自动代理端口(可选):", 
        WS_CHILD | WS_VISIBLE, left, y, 140, 20, hwnd_, (HMENU)IDC_STATIC_SETTINGS_LABEL, hInstance_, NULL);
    SendMessage(hLbl1, WM_SETFONT, (WPARAM)hFont, TRUE);
    SetWindowTheme(hLbl1, L"", L"");
    
    HWND hEdit1 = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", 
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | ES_NUMBER, 
        left + 145, y, 135, 24, hwnd_, (HMENU)IDC_EDIT_SETTINGS_AUTO_PORT, hInstance_, NULL);
    SendMessage(hEdit1, WM_SETFONT, (WPARAM)hFont, TRUE);
    SetWindowTheme(hEdit1, L"", L"");
    Utils::SetToolTip(hToolTip_, hEdit1, L"应用提供的HTTP自动代理PAC服务端口，留空或0表示不启用");
    
    y += 35;
    
    // 日志保留天数
    HWND hLbl3 = CreateWindowExW(0, L"STATIC", L"日志保留天数:", 
        WS_CHILD | WS_VISIBLE, left, y, 120, 20, hwnd_, (HMENU)IDC_STATIC_SETTINGS_LOG_DAYS, hInstance_, NULL);
    SendMessage(hLbl3, WM_SETFONT, (WPARAM)hFont, TRUE);
    SetWindowTheme(hLbl3, L"", L"");
    
    HWND hEdit3 = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", 
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | ES_NUMBER, 
        left + 130, y, 150, 24, hwnd_, (HMENU)IDC_EDIT_SETTINGS_LOG_DAYS, hInstance_, NULL);
    SendMessage(hEdit3, WM_SETFONT, (WPARAM)hFont, TRUE);
    SetWindowTheme(hEdit3, L"", L"");
    Utils::SetToolTip(hToolTip_, hEdit3, L"系统日志保留的天数，超过此天数的历史记录将被自动清理");
    
    y += 35;
    
    // 缓冲区大小
    HWND hLbl4 = CreateWindowExW(0, L"STATIC", L"转发缓冲区大小 (KB):", 
        WS_CHILD | WS_VISIBLE, left, y, 150, 20, hwnd_, (HMENU)IDC_STATIC_SETTINGS_BUFFER_SIZE, hInstance_, NULL);
    SendMessage(hLbl4, WM_SETFONT, (WPARAM)hFont, TRUE);
    SetWindowTheme(hLbl4, L"", L"");
    
    HWND hEdit4 = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", 
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | ES_NUMBER, 
        left + 160, y, 120, 24, hwnd_, (HMENU)IDC_EDIT_SETTINGS_BUFFER_SIZE, hInstance_, NULL);
    SendMessage(hEdit4, WM_SETFONT, (WPARAM)hFont, TRUE);
    SetWindowTheme(hEdit4, L"", L"");
    Utils::SetToolTip(hToolTip_, hEdit4, L"数据转发时使用的缓冲区大小，推荐值 128~512");
    
    // 提示文字
    HWND hLblTip = CreateWindowExW(0, L"STATIC", L"(0=禁用缓冲, 建议128-512)", 
        WS_CHILD | WS_VISIBLE, left + 290, y, 200, 20, hwnd_, (HMENU)10099, hInstance_, NULL);
    SendMessage(hLblTip, WM_SETFONT, (WPARAM)hFont, TRUE);
    SetWindowTheme(hLblTip, L"", L"");
    
    y += 40;
    
    // TCPing检测目标
    HWND hLbl2 = CreateWindowExW(0, L"STATIC", L"TCPing检测目标 (每行一个 host:port):", 
        WS_CHILD | WS_VISIBLE, left, y, 300, 20, hwnd_, (HMENU)IDC_STATIC_SETTINGS_TCPING, hInstance_, NULL);
    SendMessage(hLbl2, WM_SETFONT, (WPARAM)hFont, TRUE);
    SetWindowTheme(hLbl2, L"", L"");
    
    y += 25;
    
    // 计算 TCPing 文本框高度 - 调整为原来的 1/3
    int remainingHeight = btnTop - y - 10;
    int tcpingHeight = remainingHeight / 3;  // 1/3 高度
    if (tcpingHeight < 60) tcpingHeight = 60;  // 最小高度
    
    HWND hEdit2 = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", 
        WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL | WS_VSCROLL | ES_WANTRETURN, 
        left, y, width, tcpingHeight, hwnd_, (HMENU)IDC_EDIT_SETTINGS_TCPING, hInstance_, NULL);
    SendMessage(hEdit2, WM_SETFONT, (WPARAM)hFont, TRUE);
    SetWindowTheme(hEdit2, L"", L"");
    Utils::SetToolTip(hToolTip_, hEdit2, L"用于检测上游代理连通性的TCPing目标列表，每行填写一个例如 [api.github.com:443]");
    
    // 保存按钮
    HWND hBtn = CreateWindowExW(0, L"BUTTON", L"保存设置", 
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, left, btnTop, 100, 30, hwnd_, (HMENU)IDC_BTN_SAVE_SETTINGS, hInstance_, NULL);
    SendMessage(hBtn, WM_SETFONT, (WPARAM)hFont, TRUE);
    SetWindowTheme(hBtn, L"", L"");
    Utils::SetToolTip(hToolTip_, hBtn, L"保存全局系统配置");
    
    // 加载已保存的配置
    std::string portStr = Database::Instance().GetConfig("auto_proxy_port", "");
    SetWindowTextA(hEdit1, portStr.c_str());
    
    std::string logDaysStr = Database::Instance().GetConfig("log_retention_days", "30");
    SetWindowTextA(hEdit3, logDaysStr.c_str());
    
    std::string bufferSizeStr = Database::Instance().GetConfig("relay_buffer_size_kb", "128");
    SetWindowTextA(hEdit4, bufferSizeStr.c_str());
    
    std::string targets = Database::Instance().GetConfig("tcping_targets", "www.google.com:443\r\nwww.facebook.com:443\r\nwww.x.com:443");
    SetWindowTextA(hEdit2, targets.c_str());
}

void MainWindow::SaveSettings() {
    // 获取自动代理端口
    int len1 = GetWindowTextLengthA(GetDlgItem(hwnd_, IDC_EDIT_SETTINGS_AUTO_PORT));
    std::string portStr(len1 + 1, '\0');
    GetWindowTextA(GetDlgItem(hwnd_, IDC_EDIT_SETTINGS_AUTO_PORT), &portStr[0], len1 + 1);
    portStr.resize(len1);
    Database::Instance().SetConfig("auto_proxy_port", portStr);
    
    // 获取日志保留天数
    int len3 = GetWindowTextLengthA(GetDlgItem(hwnd_, IDC_EDIT_SETTINGS_LOG_DAYS));
    std::string logDaysStr(len3 + 1, '\0');
    GetWindowTextA(GetDlgItem(hwnd_, IDC_EDIT_SETTINGS_LOG_DAYS), &logDaysStr[0], len3 + 1);
    logDaysStr.resize(len3);
    int logDays = std::atoi(logDaysStr.c_str());
    if (logDays <= 0) logDays = 30;  // 默认30天
    Database::Instance().SetConfig("log_retention_days", std::to_string(logDays));
    
    // 获取缓冲区大小
    int len4 = GetWindowTextLengthA(GetDlgItem(hwnd_, IDC_EDIT_SETTINGS_BUFFER_SIZE));
    std::string bufferSizeStr(len4 + 1, '\0');
    GetWindowTextA(GetDlgItem(hwnd_, IDC_EDIT_SETTINGS_BUFFER_SIZE), &bufferSizeStr[0], len4 + 1);
    bufferSizeStr.resize(len4);
    int bufferSize = std::atoi(bufferSizeStr.c_str());
    if (bufferSize < 0) bufferSize = 0;
    if (bufferSize > 4096) bufferSize = 4096;  // 最大4MB
    Database::Instance().SetConfig("relay_buffer_size_kb", std::to_string(bufferSize));
    
    // 获取TCPing目标
    int len2 = GetWindowTextLengthA(GetDlgItem(hwnd_, IDC_EDIT_SETTINGS_TCPING));
    std::string targets(len2 + 1, '\0');
    GetWindowTextA(GetDlgItem(hwnd_, IDC_EDIT_SETTINGS_TCPING), &targets[0], len2 + 1);
    targets.resize(len2);
    Database::Instance().SetConfig("tcping_targets", targets);
    
    // 重载配置
    ProxyServer::Instance().ReloadPorts();
    
    MessageBoxW(hwnd_, L"系统设置已保存", L"提示", MB_OK);
}

