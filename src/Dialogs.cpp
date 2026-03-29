#include "MainWindow.h"
#include "Database.h"
#include "ProxyServer.h"
#include "Utils.h"
#include "Version.h"
#include <windowsx.h>
#include <commctrl.h>
#include <shellapi.h>

// 对话框控件ID
#define IDC_EDIT_USERNAME   101
#define IDC_EDIT_PASSWORD   102
#define IDC_EDIT_IPS        103
#define IDC_EDIT_DAILY      104
#define IDC_EDIT_MONTHLY    105
#define IDC_CHK_ENABLED     106
#define IDC_EDIT_REMARK     107
#define IDC_EDIT_EXPIRY     108

#define IDC_EDIT_LISTEN     201
#define IDC_COMBO_TYPE      202
#define IDC_EDIT_HOST       203
#define IDC_EDIT_PORT       204
#define IDC_EDIT_USER       205
#define IDC_EDIT_PASS       206
#define IDC_EDIT_DESC       207
#define IDC_CHK_PORT_ENABLE 208

#define IDC_EDIT_AUTO_PORT  301
#define IDC_EDIT_TCPING     302

static UserInfo g_editUser;
static ProxyPort g_editPort;
static bool g_isEditMode = false;
static bool g_dialogResult = false;
static bool g_dialogClosed = false;  // 标记对话框是否已关闭

// 用户对话框窗口过程
static LRESULT CALLBACK UserDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_COMMAND:
        if (HIWORD(wParam) == BN_CLICKED) {
            int id = LOWORD(wParam);
            if (id == IDOK) {
                wchar_t buffer[256];
                GetDlgItemTextW(hDlg, IDC_EDIT_USERNAME, buffer, 256);
                g_editUser.username = Utils::WStringToString(buffer);
                GetDlgItemTextW(hDlg, IDC_EDIT_PASSWORD, buffer, 256);
                g_editUser.password = Utils::WStringToString(buffer);
                GetDlgItemTextW(hDlg, IDC_EDIT_IPS, buffer, 256);
                g_editUser.allowedIPs = Utils::WStringToString(buffer);
                GetDlgItemTextW(hDlg, IDC_EDIT_DAILY, buffer, 256);
                g_editUser.dailyLimit = _wtoi64(buffer) * 1024 * 1024;
                GetDlgItemTextW(hDlg, IDC_EDIT_MONTHLY, buffer, 256);
                g_editUser.monthlyLimit = _wtoi64(buffer) * 1024 * 1024;
                g_editUser.enabled = IsDlgButtonChecked(hDlg, IDC_CHK_ENABLED) == BST_CHECKED;
                GetDlgItemTextW(hDlg, IDC_EDIT_REMARK, buffer, 256);
                g_editUser.remark = Utils::WStringToString(buffer);
                GetDlgItemTextW(hDlg, IDC_EDIT_EXPIRY, buffer, 256);
                g_editUser.expiryDate = Utils::WStringToString(buffer);
                
                if (g_editUser.username.empty()) {
                    MessageBoxW(hDlg, L"用户名不能为空", L"错误", MB_OK | MB_ICONERROR);
                    return 0;
                }
                if (g_editUser.password.empty() && (g_editUser.allowedIPs.empty() || g_editUser.allowedIPs == "*")) {
                    MessageBoxW(hDlg, L"如果不设置密码，则必须设置具体的允许 IP 以启用 IP 免密登录", L"错误", MB_OK | MB_ICONERROR);
                    return 0;
                }
                g_dialogResult = true;
                g_dialogClosed = true;
                DestroyWindow(hDlg);
                return 0;
            } else if (id == IDCANCEL) {
                g_dialogResult = false;
                g_dialogClosed = true;
                DestroyWindow(hDlg);
                return 0;
            }
        }
        break;
        
    case WM_CLOSE:
        g_dialogResult = false;
        g_dialogClosed = true;
        DestroyWindow(hDlg);
        return 0;
    }
    return DefWindowProc(hDlg, msg, wParam, lParam);
}

// 端口对话框窗口过程
static LRESULT CALLBACK PortDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_COMMAND:
        if (HIWORD(wParam) == BN_CLICKED) {
            int id = LOWORD(wParam);
            if (id == IDOK) {
                wchar_t buffer[256];
                GetDlgItemTextW(hDlg, IDC_EDIT_LISTEN, buffer, 256);
                g_editPort.listenPort = _wtoi(buffer);  // 0 或负数都表示不启用监听
                if (g_editPort.listenPort < 0) g_editPort.listenPort = 0;
                
                HWND hCombo = GetDlgItem(hDlg, IDC_COMBO_TYPE);
                int sel = (int)SendMessageW(hCombo, CB_GETCURSEL, 0, 0);
                g_editPort.upstreamType = sel == 1 ? "socks5" : "http";
                
                GetDlgItemTextW(hDlg, IDC_EDIT_HOST, buffer, 256);
                g_editPort.upstreamHost = Utils::WStringToString(buffer);
                GetDlgItemTextW(hDlg, IDC_EDIT_PORT, buffer, 256);
                g_editPort.upstreamPort = _wtoi(buffer);
                GetDlgItemTextW(hDlg, IDC_EDIT_USER, buffer, 256);
                g_editPort.upstreamUser = Utils::WStringToString(buffer);
                GetDlgItemTextW(hDlg, IDC_EDIT_PASS, buffer, 256);
                g_editPort.upstreamPass = Utils::WStringToString(buffer);
                GetDlgItemTextW(hDlg, IDC_EDIT_DESC, buffer, 256);
                g_editPort.description = Utils::WStringToString(buffer);
                g_editPort.enabled = IsDlgButtonChecked(hDlg, IDC_CHK_PORT_ENABLE) == BST_CHECKED;
                
                // 验证：上游地址和端口是必填的，监听端口可选（0表示不监听）
                if (g_editPort.upstreamHost.empty() || g_editPort.upstreamPort <= 0) {
                    MessageBoxW(hDlg, L"请填写上游地址和端口", L"错误", MB_OK | MB_ICONERROR);
                    return 0;
                }
                g_dialogResult = true;
                g_dialogClosed = true;
                DestroyWindow(hDlg);
                return 0;
            } else if (id == IDCANCEL) {
                g_dialogResult = false;
                g_dialogClosed = true;
                DestroyWindow(hDlg);
                return 0;
            }
        }
        break;
        
    case WM_CLOSE:
        g_dialogResult = false;
        g_dialogClosed = true;
        DestroyWindow(hDlg);
        return 0;
    }
    return DefWindowProc(hDlg, msg, wParam, lParam);
}

// 注册对话框窗口类
static bool RegisterDialogClass(HINSTANCE hInstance) {
    static bool registered = false;
    if (registered) return true;
    
    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = UserDlgProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"UserDialogClass";
    if (!RegisterClassExW(&wc)) return false;
    
    wc.lpfnWndProc = PortDlgProc;
    wc.lpszClassName = L"PortDialogClass";
    if (!RegisterClassExW(&wc)) return false;
    
    registered = true;
    return true;
}

// 创建用户对话框
static HWND CreateUserDialogWindow(HWND hParent, HINSTANCE hInstance) {
    RegisterDialogClass(hInstance);
    
    HFONT hFont = CreateFontW(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei UI");
    
    HWND hDlg = CreateWindowExW(WS_EX_DLGMODALFRAME, L"UserDialogClass", 
        g_isEditMode ? L"编辑用户" : L"添加用户",
        WS_POPUP | WS_CAPTION | WS_SYSMENU,
        0, 0, 350, 400, hParent, nullptr, hInstance, nullptr);  // 增加高度
    
    HWND hToolTip = Utils::CreateToolTip(hDlg);
    
    int y = 20;
    
    // 用户名
    HWND h = CreateWindowW(L"STATIC", L"用户名:", WS_CHILD | WS_VISIBLE,
        20, y, 80, 20, hDlg, nullptr, hInstance, nullptr);
    SendMessage(h, WM_SETFONT, (WPARAM)hFont, TRUE);
    h = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
        110, y, 200, 24, hDlg, (HMENU)IDC_EDIT_USERNAME, hInstance, nullptr);
    SendMessage(h, WM_SETFONT, (WPARAM)hFont, TRUE);
    Utils::SetToolTip(hToolTip, h, L"代理代理客户端验证登录需要的用户名（必填）");
    y += 35;
    
    // 密码
    h = CreateWindowW(L"STATIC", L"密码:", WS_CHILD | WS_VISIBLE,
        20, y, 80, 20, hDlg, nullptr, hInstance, nullptr);
    SendMessage(h, WM_SETFONT, (WPARAM)hFont, TRUE);
    h = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
        110, y, 200, 24, hDlg, (HMENU)IDC_EDIT_PASSWORD, hInstance, nullptr);
    SendMessage(h, WM_SETFONT, (WPARAM)hFont, TRUE);
    Utils::SetToolTip(hToolTip, h, L"代理代理客户端验证登录需要的密码，留空则针对允许的IP进行免密认证");
    y += 35;
    
    // 允许IP
    h = CreateWindowW(L"STATIC", L"允许IP:", WS_CHILD | WS_VISIBLE,
        20, y, 80, 20, hDlg, nullptr, hInstance, nullptr);
    SendMessage(h, WM_SETFONT, (WPARAM)hFont, TRUE);
    h = CreateWindowW(L"EDIT", L"*", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
        110, y, 200, 24, hDlg, (HMENU)IDC_EDIT_IPS, hInstance, nullptr);
    SendMessage(h, WM_SETFONT, (WPARAM)hFont, TRUE);
    Utils::SetToolTip(hToolTip, h, L"允许连接的IP地址，支持CIDR段如192.168.1.0/24，多个IP逗号分隔，星号*表示允许所有IP");
    y += 35;
    
    // 每日限额
    h = CreateWindowW(L"STATIC", L"每日限额(MB):", WS_CHILD | WS_VISIBLE,
        20, y, 90, 20, hDlg, nullptr, hInstance, nullptr);
    SendMessage(h, WM_SETFONT, (WPARAM)hFont, TRUE);
    h = CreateWindowW(L"EDIT", L"0", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL | ES_NUMBER,
        110, y, 200, 24, hDlg, (HMENU)IDC_EDIT_DAILY, hInstance, nullptr);
    SendMessage(h, WM_SETFONT, (WPARAM)hFont, TRUE);
    Utils::SetToolTip(hToolTip, h, L"此用户每天可使用的最大流量，超出后当天封禁。单位MB，0表示不限制");
    y += 35;
    
    // 每月限额
    h = CreateWindowW(L"STATIC", L"每月限额(MB):", WS_CHILD | WS_VISIBLE,
        20, y, 90, 20, hDlg, nullptr, hInstance, nullptr);
    SendMessage(h, WM_SETFONT, (WPARAM)hFont, TRUE);
    h = CreateWindowW(L"EDIT", L"0", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL | ES_NUMBER,
        110, y, 200, 24, hDlg, (HMENU)IDC_EDIT_MONTHLY, hInstance, nullptr);
    SendMessage(h, WM_SETFONT, (WPARAM)hFont, TRUE);
    Utils::SetToolTip(hToolTip, h, L"此用户每月可使用的最大流量，超出后本月内暂停服务。单位MB，0表示不限制");
    y += 35;
    
    // 备注
    h = CreateWindowW(L"STATIC", L"备注:", WS_CHILD | WS_VISIBLE,
        20, y, 80, 20, hDlg, nullptr, hInstance, nullptr);
    SendMessage(h, WM_SETFONT, (WPARAM)hFont, TRUE);
    h = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
        110, y, 200, 24, hDlg, (HMENU)IDC_EDIT_REMARK, hInstance, nullptr);
    SendMessage(h, WM_SETFONT, (WPARAM)hFont, TRUE);
    Utils::SetToolTip(hToolTip, h, L"为用户添加方便识别的备注说明");
    y += 35;
    
    // 到期日期
    h = CreateWindowW(L"STATIC", L"到期日期:", WS_CHILD | WS_VISIBLE,
        20, y, 80, 20, hDlg, nullptr, hInstance, nullptr);
    SendMessage(h, WM_SETFONT, (WPARAM)hFont, TRUE);
    h = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
        110, y, 200, 24, hDlg, (HMENU)IDC_EDIT_EXPIRY, hInstance, nullptr);
    SendMessage(h, WM_SETFONT, (WPARAM)hFont, TRUE);
    Utils::SetToolTip(hToolTip, h, L"账号到期自动停用的日期，格式为 yyyy-mm-dd，留空表示永久有效。");
    // 提示文本
    h = CreateWindowW(L"STATIC", L"(格式 yyyy-mm-dd，留空不限制)", WS_CHILD | WS_VISIBLE,
        110, y+25, 200, 15, hDlg, nullptr, hInstance, nullptr);
    HFONT hFontSmall = CreateFontW(12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei UI");
    SendMessage(h, WM_SETFONT, (WPARAM)hFontSmall, TRUE);
    y += 40;
    
    // 启用
    h = CreateWindowW(L"BUTTON", L"启用", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        110, y, 80, 24, hDlg, (HMENU)IDC_CHK_ENABLED, hInstance, nullptr);
    SendMessage(h, WM_SETFONT, (WPARAM)hFont, TRUE);
    CheckDlgButton(hDlg, IDC_CHK_ENABLED, BST_CHECKED);
    y += 40;
    
    // 按钮
    h = CreateWindowW(L"BUTTON", L"确定", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
        80, y, 80, 28, hDlg, (HMENU)IDOK, hInstance, nullptr);
    SendMessage(h, WM_SETFONT, (WPARAM)hFont, TRUE);
    
    h = CreateWindowW(L"BUTTON", L"取消", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        180, y, 80, 28, hDlg, (HMENU)IDCANCEL, hInstance, nullptr);
    SendMessage(h, WM_SETFONT, (WPARAM)hFont, TRUE);
    
    return hDlg;
}

// 创建端口对话框
static HWND CreatePortDialogWindow(HWND hParent, HINSTANCE hInstance) {
    RegisterDialogClass(hInstance);
    
    HFONT hFont = CreateFontW(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei UI");
    
    HWND hDlg = CreateWindowExW(WS_EX_DLGMODALFRAME, L"PortDialogClass", 
        g_isEditMode ? L"编辑端口" : L"添加端口",
        WS_POPUP | WS_CAPTION | WS_SYSMENU,
        0, 0, 400, 400, hParent, nullptr, hInstance, nullptr);
        
    HWND hToolTip = Utils::CreateToolTip(hDlg);
    
    int y = 20;
    
    // 监听端口 (可选，0表示不监听)
    HWND h = CreateWindowW(L"STATIC", L"监听端口(可选):", WS_CHILD | WS_VISIBLE,
        20, y, 100, 20, hDlg, nullptr, hInstance, nullptr);
    SendMessage(h, WM_SETFONT, (WPARAM)hFont, TRUE);
    h = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL | ES_NUMBER,
        130, y, 220, 24, hDlg, (HMENU)IDC_EDIT_LISTEN, hInstance, nullptr);
    SendMessage(h, WM_SETFONT, (WPARAM)hFont, TRUE);
    Utils::SetToolTip(hToolTip, h, L"作为二级代理的服务端口。为0或者不填时，意味着这只是一个被路由引用的节点，而不单独开启端口监听。");
    y += 35;
    
    // 上游类型
    h = CreateWindowW(L"STATIC", L"上游类型:", WS_CHILD | WS_VISIBLE,
        20, y, 100, 20, hDlg, nullptr, hInstance, nullptr);
    SendMessage(h, WM_SETFONT, (WPARAM)hFont, TRUE);
    HWND hCombo = CreateWindowW(L"COMBOBOX", L"", WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST,
        130, y, 220, 100, hDlg, (HMENU)IDC_COMBO_TYPE, hInstance, nullptr);
    SendMessage(hCombo, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessageW(hCombo, CB_ADDSTRING, 0, (LPARAM)L"http");
    SendMessageW(hCombo, CB_ADDSTRING, 0, (LPARAM)L"socks5");
    SendMessageW(hCombo, CB_SETCURSEL, 0, 0);
    Utils::SetToolTip(hToolTip, hCombo, L"上游代理服务支持的协议，如 http/socks5");
    y += 35;
    
    // 上游地址
    h = CreateWindowW(L"STATIC", L"上游地址:", WS_CHILD | WS_VISIBLE,
        20, y, 100, 20, hDlg, nullptr, hInstance, nullptr);
    SendMessage(h, WM_SETFONT, (WPARAM)hFont, TRUE);
    h = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
        130, y, 220, 24, hDlg, (HMENU)IDC_EDIT_HOST, hInstance, nullptr);
    SendMessage(h, WM_SETFONT, (WPARAM)hFont, TRUE);
    Utils::SetToolTip(hToolTip, h, L"上游代理服务的IP地址或域名，例如 192.168.1.100");
    y += 35;
    
    // 上游端口
    h = CreateWindowW(L"STATIC", L"上游端口:", WS_CHILD | WS_VISIBLE,
        20, y, 100, 20, hDlg, nullptr, hInstance, nullptr);
    SendMessage(h, WM_SETFONT, (WPARAM)hFont, TRUE);
    h = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL | ES_NUMBER,
        130, y, 220, 24, hDlg, (HMENU)IDC_EDIT_PORT, hInstance, nullptr);
    SendMessage(h, WM_SETFONT, (WPARAM)hFont, TRUE);
    Utils::SetToolTip(hToolTip, h, L"上游代理服务的端口，例如 1080");
    y += 35;
    
    // 上游用户名
    h = CreateWindowW(L"STATIC", L"上游用户名:", WS_CHILD | WS_VISIBLE,
        20, y, 100, 20, hDlg, nullptr, hInstance, nullptr);
    SendMessage(h, WM_SETFONT, (WPARAM)hFont, TRUE);
    h = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
        130, y, 220, 24, hDlg, (HMENU)IDC_EDIT_USER, hInstance, nullptr);
    SendMessage(h, WM_SETFONT, (WPARAM)hFont, TRUE);
    Utils::SetToolTip(hToolTip, h, L"如果上游代理服务需要认证，这里填写用户名，不需要时留空");
    y += 35;
    
    // 上游密码
    h = CreateWindowW(L"STATIC", L"上游密码:", WS_CHILD | WS_VISIBLE,
        20, y, 100, 20, hDlg, nullptr, hInstance, nullptr);
    SendMessage(h, WM_SETFONT, (WPARAM)hFont, TRUE);
    h = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL | ES_PASSWORD,
        130, y, 220, 24, hDlg, (HMENU)IDC_EDIT_PASS, hInstance, nullptr);
    SendMessage(h, WM_SETFONT, (WPARAM)hFont, TRUE);
    Utils::SetToolTip(hToolTip, h, L"如果上游代理服务需要认证，这里填写密码，不需要时留空");
    y += 35;
    
    // 描述
    h = CreateWindowW(L"STATIC", L"描述:", WS_CHILD | WS_VISIBLE,
        20, y, 100, 20, hDlg, nullptr, hInstance, nullptr);
    SendMessage(h, WM_SETFONT, (WPARAM)hFont, TRUE);
    h = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
        130, y, 220, 24, hDlg, (HMENU)IDC_EDIT_DESC, hInstance, nullptr);
    SendMessage(h, WM_SETFONT, (WPARAM)hFont, TRUE);
    Utils::SetToolTip(hToolTip, h, L"方便识别和管理的端口描述备注");
    y += 35;
    
    // 启用
    h = CreateWindowW(L"BUTTON", L"启用", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        130, y, 80, 24, hDlg, (HMENU)IDC_CHK_PORT_ENABLE, hInstance, nullptr);
    SendMessage(h, WM_SETFONT, (WPARAM)hFont, TRUE);
    CheckDlgButton(hDlg, IDC_CHK_PORT_ENABLE, BST_CHECKED);
    y += 40;
    
    // 按钮
    h = CreateWindowW(L"BUTTON", L"确定", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
        100, y, 80, 28, hDlg, (HMENU)IDOK, hInstance, nullptr);
    SendMessage(h, WM_SETFONT, (WPARAM)hFont, TRUE);
    
    h = CreateWindowW(L"BUTTON", L"取消", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        200, y, 80, 28, hDlg, (HMENU)IDCANCEL, hInstance, nullptr);
    SendMessage(h, WM_SETFONT, (WPARAM)hFont, TRUE);
    
    return hDlg;
}

// 运行模态对话框 - 使用标志变量而非PostQuitMessage
static bool RunModalDialog(HWND hDlg, HWND hParent) {
    // 居中
    RECT rc, rcOwner;
    GetWindowRect(hParent, &rcOwner);
    GetWindowRect(hDlg, &rc);
    int x = rcOwner.left + (rcOwner.right - rcOwner.left - (rc.right - rc.left)) / 2;
    int y = rcOwner.top + (rcOwner.bottom - rcOwner.top - (rc.bottom - rc.top)) / 2;
    SetWindowPos(hDlg, nullptr, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
    
    ShowWindow(hDlg, SW_SHOW);
    EnableWindow(hParent, FALSE);
    
    g_dialogClosed = false;
    
    MSG msg;
    while (!g_dialogClosed && GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    EnableWindow(hParent, TRUE);
    SetForegroundWindow(hParent);
    
    return g_dialogResult;
}

void MainWindow::ShowAddUserDialog() {
    g_isEditMode = false;
    g_editUser = UserInfo();
    g_dialogResult = false;
    
    HWND hDlg = CreateUserDialogWindow(hwnd_, hInstance_);
    if (!hDlg) return;
    
    if (RunModalDialog(hDlg, hwnd_)) {
        Database::Instance().AddUser(g_editUser);
        RefreshUserList();
    }
}

void MainWindow::ShowEditUserDialog() {
    int sel = ListView_GetNextItem(hUserList_, -1, LVNI_SELECTED);
    if (sel < 0) {
        MessageBoxW(hwnd_, L"请先选择一个用户", L"提示", MB_OK | MB_ICONINFORMATION);
        return;
    }
    
    wchar_t buffer[32];
    ListView_GetItemText(hUserList_, sel, 0, buffer, 32);
    int userId = _wtoi(buffer);
    
    if (!Database::Instance().GetUser(userId, g_editUser)) {
        return;
    }
    
    g_isEditMode = true;
    g_dialogResult = false;
    
    HWND hDlg = CreateUserDialogWindow(hwnd_, hInstance_);
    if (!hDlg) return;
    
    // 填充数据
    SetDlgItemTextW(hDlg, IDC_EDIT_USERNAME, Utils::StringToWString(g_editUser.username).c_str());
    SetDlgItemTextW(hDlg, IDC_EDIT_PASSWORD, Utils::StringToWString(g_editUser.password).c_str());
    SetDlgItemTextW(hDlg, IDC_EDIT_IPS, Utils::StringToWString(g_editUser.allowedIPs).c_str());
    SetDlgItemTextW(hDlg, IDC_EDIT_DAILY, std::to_wstring(g_editUser.dailyLimit / (1024*1024)).c_str());
    SetDlgItemTextW(hDlg, IDC_EDIT_MONTHLY, std::to_wstring(g_editUser.monthlyLimit / (1024*1024)).c_str());
    SetDlgItemTextW(hDlg, IDC_EDIT_REMARK, Utils::StringToWString(g_editUser.remark).c_str());
    SetDlgItemTextW(hDlg, IDC_EDIT_EXPIRY, Utils::StringToWString(g_editUser.expiryDate).c_str());
    CheckDlgButton(hDlg, IDC_CHK_ENABLED, g_editUser.enabled ? BST_CHECKED : BST_UNCHECKED);
    
    if (RunModalDialog(hDlg, hwnd_)) {
        Database::Instance().UpdateUser(g_editUser);
        RefreshUserList();
    }
}

void MainWindow::DeleteSelectedUser() {
    int sel = ListView_GetNextItem(hUserList_, -1, LVNI_SELECTED);
    if (sel < 0) {
        MessageBoxW(hwnd_, L"请先选择一个用户", L"提示", MB_OK | MB_ICONINFORMATION);
        return;
    }
    
    if (MessageBoxW(hwnd_, L"确定要删除选中的用户吗？", L"确认", MB_YESNO | MB_ICONQUESTION) == IDYES) {
        wchar_t buffer[32];
        ListView_GetItemText(hUserList_, sel, 0, buffer, 32);
        int userId = _wtoi(buffer);
        Database::Instance().DeleteUser(userId);
        RefreshUserList();
    }
}

void MainWindow::ShowAddPortDialog() {
    g_isEditMode = false;
    g_editPort = ProxyPort();
    g_dialogResult = false;
    
    HWND hDlg = CreatePortDialogWindow(hwnd_, hInstance_);
    if (!hDlg) return;
    
    if (RunModalDialog(hDlg, hwnd_)) {
        Database::Instance().AddProxyPort(g_editPort);
        RefreshPortList();
        ProxyServer::Instance().ReloadPorts();  // 自动重载
    }
}

void MainWindow::ShowEditPortDialog() {
    int sel = ListView_GetNextItem(hPortList_, -1, LVNI_SELECTED);
    if (sel < 0) {
        MessageBoxW(hwnd_, L"请先选择一个端口", L"提示", MB_OK | MB_ICONINFORMATION);
        return;
    }
    
    wchar_t buffer[32];
    ListView_GetItemText(hPortList_, sel, 0, buffer, 32);
    int portId = _wtoi(buffer);
    
    if (!Database::Instance().GetProxyPort(portId, g_editPort)) {
        return;
    }
    
    g_isEditMode = true;
    g_dialogResult = false;
    
    HWND hDlg = CreatePortDialogWindow(hwnd_, hInstance_);
    if (!hDlg) return;
    
    // 填充数据 - 监听端口为0时显示空字符串
    if (g_editPort.listenPort > 0) {
        SetDlgItemTextW(hDlg, IDC_EDIT_LISTEN, std::to_wstring(g_editPort.listenPort).c_str());
    } else {
        SetDlgItemTextW(hDlg, IDC_EDIT_LISTEN, L"");
    }
    HWND hCombo = GetDlgItem(hDlg, IDC_COMBO_TYPE);
    SendMessageW(hCombo, CB_SETCURSEL, g_editPort.upstreamType == "socks5" ? 1 : 0, 0);
    SetDlgItemTextW(hDlg, IDC_EDIT_HOST, Utils::StringToWString(g_editPort.upstreamHost).c_str());
    SetDlgItemTextW(hDlg, IDC_EDIT_PORT, std::to_wstring(g_editPort.upstreamPort).c_str());
    SetDlgItemTextW(hDlg, IDC_EDIT_USER, Utils::StringToWString(g_editPort.upstreamUser).c_str());
    SetDlgItemTextW(hDlg, IDC_EDIT_PASS, Utils::StringToWString(g_editPort.upstreamPass).c_str());
    SetDlgItemTextW(hDlg, IDC_EDIT_DESC, Utils::StringToWString(g_editPort.description).c_str());
    CheckDlgButton(hDlg, IDC_CHK_PORT_ENABLE, g_editPort.enabled ? BST_CHECKED : BST_UNCHECKED);
    
    if (RunModalDialog(hDlg, hwnd_)) {
        Database::Instance().UpdateProxyPort(g_editPort);
        RefreshPortList();
        ProxyServer::Instance().ReloadPorts();  // 自动重载
    }
}

void MainWindow::DeleteSelectedPort() {
    int sel = ListView_GetNextItem(hPortList_, -1, LVNI_SELECTED);
    if (sel < 0) {
        MessageBoxW(hwnd_, L"请先选择一个端口", L"提示", MB_OK | MB_ICONINFORMATION);
        return;
    }
    
    if (MessageBoxW(hwnd_, L"确定要删除选中的端口吗？", L"确认", MB_YESNO | MB_ICONQUESTION) == IDYES) {
        wchar_t buffer[32];
        ListView_GetItemText(hPortList_, sel, 0, buffer, 32);
        int portId = _wtoi(buffer);
        Database::Instance().DeleteProxyPort(portId);
        RefreshPortList();
        ProxyServer::Instance().ReloadPorts();  // 自动重载
    }
}

void MainWindow::MoveSelectedUserUp() {
    int sel = ListView_GetNextItem(hUserList_, -1, LVNI_SELECTED);
    if (sel < 0) return;
    
    wchar_t buffer[32];
    ListView_GetItemText(hUserList_, sel, 0, buffer, 32);
    int userId = _wtoi(buffer);
    
    if (Database::Instance().MoveUserUp(userId)) {
        RefreshUserList();
        int newSel = (sel > 0) ? (sel - 1) : 0;
        ListView_SetItemState(hUserList_, newSel, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_EnsureVisible(hUserList_, newSel, FALSE);
    }
}

void MainWindow::MoveSelectedUserDown() {
    int sel = ListView_GetNextItem(hUserList_, -1, LVNI_SELECTED);
    if (sel < 0) return;
    
    wchar_t buffer[32];
    ListView_GetItemText(hUserList_, sel, 0, buffer, 32);
    int userId = _wtoi(buffer);
    
    if (Database::Instance().MoveUserDown(userId)) {
        RefreshUserList();
        int newSel = sel + 1; 
        ListView_SetItemState(hUserList_, newSel, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_EnsureVisible(hUserList_, newSel, FALSE);
    }
}

void MainWindow::MoveSelectedPortUp() {
    int sel = ListView_GetNextItem(hPortList_, -1, LVNI_SELECTED);
    if (sel < 0) return;
    
    wchar_t buffer[32];
    ListView_GetItemText(hPortList_, sel, 0, buffer, 32);
    int portId = _wtoi(buffer);
    
    if (Database::Instance().MoveProxyPortUp(portId)) {
        RefreshPortList();
        int newSel = (sel > 0) ? (sel - 1) : 0;
        ListView_SetItemState(hPortList_, newSel, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_EnsureVisible(hPortList_, newSel, FALSE);
        ProxyServer::Instance().ReloadPorts();
    }
}

void MainWindow::MoveSelectedPortDown() {
    int sel = ListView_GetNextItem(hPortList_, -1, LVNI_SELECTED);
    if (sel < 0) return;
    
    wchar_t buffer[32];
    ListView_GetItemText(hPortList_, sel, 0, buffer, 32);
    int portId = _wtoi(buffer);
    
    if (Database::Instance().MoveProxyPortDown(portId)) {
        RefreshPortList();
        int newSel = sel + 1; 
        ListView_SetItemState(hPortList_, newSel, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_EnsureVisible(hPortList_, newSel, FALSE);
        ProxyServer::Instance().ReloadPorts();
    }
}

static HRESULT CALLBACK TaskDialogCallback(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam, LONG_PTR lpRefData) {
    if (msg == TDN_HYPERLINK_CLICKED) {
        ShellExecuteW(NULL, L"open", (LPCWSTR)lParam, NULL, NULL, SW_SHOW);
        return S_OK;
    }
    return S_OK;
}

void MainWindow::ShowAboutDialog() {
    std::wstring versionTitle = std::wstring(L"ProxyRelay v") + Version::GetVersionW();
    
    TASKDIALOGCONFIG config = { sizeof(config) };
    config.hwndParent = hwnd_;
    config.hInstance = hInstance_;
    config.dwFlags = TDF_ENABLE_HYPERLINKS | TDF_ALLOW_DIALOG_CANCELLATION | TDF_POSITION_RELATIVE_TO_WINDOW;
    config.pszWindowTitle = L"关于 ProxyRelay";
    config.pszMainInstruction = versionTitle.c_str();
    config.pszContent = L"二级代理管理器\n"
                        L"支持用户认证、流量统计、多端口转发\n\n"
                        L"Email: <a href=\"mailto:howard@shanghaiit.com\">howard@shanghaiit.com</a>\n"
                        L"Website: <a href=\"http://www.shanghaiit.com\">www.shanghaiit.com</a>\n"
                        L"GitHub: <a href=\"https://github.com/git-howard\">github.com/git-howard</a>\n\n"
                        L"© 2026 ProxyRelay";
    config.pszMainIcon = TD_INFORMATION_ICON;
    config.pfCallback = TaskDialogCallback;
    
    TaskDialogIndirect(&config, nullptr, nullptr, nullptr);
}

// Ban Dialog
#define IDC_EDIT_BAN_IP      401
#define IDC_EDIT_BAN_REMARK  402

static std::string g_banIP;
static std::string g_banRemark;
static int g_banType = 0;
static int g_banId = 0;
static bool g_isBanEdit = false;

static LRESULT CALLBACK BanDialogProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_COMMAND:
        if (HIWORD(wParam) == BN_CLICKED) {
            int id = LOWORD(wParam);
            if (id == IDOK) {
                wchar_t buffer[256];
                GetDlgItemTextW(hDlg, IDC_EDIT_BAN_IP, buffer, 256);
                g_banIP = Utils::WStringToString(buffer);
                GetDlgItemTextW(hDlg, IDC_EDIT_BAN_REMARK, buffer, 256);
                g_banRemark = Utils::WStringToString(buffer);
                
                if (g_banIP.empty()) {
                    MessageBoxW(hDlg, L"IP地址不能为空", L"错误", MB_OK | MB_ICONERROR);
                    return 0;
                }
                g_dialogResult = true;
                g_dialogClosed = true;
                DestroyWindow(hDlg);
                return 0;
            } else if (id == IDCANCEL) {
                g_dialogResult = false;
                g_dialogClosed = true;
                DestroyWindow(hDlg);
                return 0;
            }
        }
        break;
        
    case WM_CLOSE:
        g_dialogResult = false;
        g_dialogClosed = true;
        DestroyWindow(hDlg);
        return 0;
    }
    return DefWindowProc(hDlg, msg, wParam, lParam);
}

static HWND CreateBanDialogWindow(HWND hParent, HINSTANCE hInstance) {
    // Register class if needed
    static bool registered = false;
    if (!registered) {
        WNDCLASSEXW wc = {};
        wc.cbSize = sizeof(wc);
        wc.style = CS_HREDRAW | CS_VREDRAW;
        wc.lpfnWndProc = BanDialogProc;
        wc.hInstance = hInstance;
        wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
        wc.lpszClassName = L"BanDialogClass";
        RegisterClassExW(&wc);
        registered = true;
    }
    
    std::wstring title = g_isBanEdit ? L"修改" : L"添加";
    if (g_banType == 0) title += L"白名单";
    else if (g_banType == 1) title += L"黑名单";
    else if (g_banType == 3) title += L"免认证IP";
    
    HWND hDlg = CreateWindowExW(WS_EX_DLGMODALFRAME, L"BanDialogClass", 
        title.c_str(),
        WS_POPUP | WS_CAPTION | WS_SYSMENU,
        0, 0, 300, 200, hParent, nullptr, hInstance, nullptr);
        
    HWND hToolTip = Utils::CreateToolTip(hDlg);
    
    HFONT hFont = CreateFontW(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei UI");
        
    int y = 20;
    HWND h = CreateWindowW(L"STATIC", L"IP 地址:", WS_CHILD | WS_VISIBLE, 20, y, 60, 20, hDlg, nullptr, hInstance, nullptr);
    SendMessage(h, WM_SETFONT, (WPARAM)hFont, TRUE);
    h = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL, 90, y, 180, 24, hDlg, (HMENU)IDC_EDIT_BAN_IP, hInstance, nullptr);
    SendMessage(h, WM_SETFONT, (WPARAM)hFont, TRUE);
    Utils::SetToolTip(hToolTip, h, L"需要管理的IP地址或CIDR段");
    y += 35;
    
    h = CreateWindowW(L"STATIC", L"备注:", WS_CHILD | WS_VISIBLE, 20, y, 60, 20, hDlg, nullptr, hInstance, nullptr);
    SendMessage(h, WM_SETFONT, (WPARAM)hFont, TRUE);
    h = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL, 90, y, 180, 24, hDlg, (HMENU)IDC_EDIT_BAN_REMARK, hInstance, nullptr);
    SendMessage(h, WM_SETFONT, (WPARAM)hFont, TRUE);
    Utils::SetToolTip(hToolTip, h, L"方便识别的注释信息");
    y += 40;
    
    if (g_isBanEdit) {
        SetDlgItemTextW(hDlg, IDC_EDIT_BAN_IP, Utils::StringToWString(g_banIP).c_str());
        SetDlgItemTextW(hDlg, IDC_EDIT_BAN_REMARK, Utils::StringToWString(g_banRemark).c_str());
    }
    
    // Buttons
    h = CreateWindowW(L"BUTTON", L"确定", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON, 60, y, 80, 28, hDlg, (HMENU)IDOK, hInstance, nullptr);
    SendMessage(h, WM_SETFONT, (WPARAM)hFont, TRUE);
    h = CreateWindowW(L"BUTTON", L"取消", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 160, y, 80, 28, hDlg, (HMENU)IDCANCEL, hInstance, nullptr);
    SendMessage(h, WM_SETFONT, (WPARAM)hFont, TRUE);
    
    return hDlg;
}

void MainWindow::ShowAddBanDialog() {
    if (currentBanType_ == 2) {
        MessageBoxW(hwnd_, L"自动封禁列表由系统管理，无法手动添加。", L"提示", MB_OK | MB_ICONINFORMATION);
        return;
    }
    
    g_banType = currentBanType_;
    g_banIP = "";
    g_banRemark = "";
    g_isBanEdit = false;
    g_dialogResult = false;
    
    HWND hDlg = CreateBanDialogWindow(hwnd_, hInstance_);
    if (!hDlg) return;
    
    if (RunModalDialog(hDlg, hwnd_)) {
        if (g_banType == 0) {
            Database::Instance().AddToWhitelist(g_banIP, g_banRemark);
        } else if (g_banType == 1) {
            Database::Instance().AddToBlacklist(g_banIP, g_banRemark);
        } else if (g_banType == 3) {
            Database::Instance().AddToNoAuthList(g_banIP, g_banRemark);
        }
        RefreshBanList();
    }
}

void MainWindow::ShowEditBanDialog() {
    if (currentBanType_ == 2) {
        MessageBoxW(hwnd_, L"自动封禁记录由系统产生，无法修改回复。", L"提示", MB_OK | MB_ICONINFORMATION);
        return;
    }

    int sel = ListView_GetNextItem(hBanList_, -1, LVNI_SELECTED);
    if (sel < 0) return;

    wchar_t buf[256];
    ListView_GetItemText(hBanList_, sel, 0, buf, 256);
    g_banId = std::stoi(buf);
    ListView_GetItemText(hBanList_, sel, 1, buf, 256);
    g_banIP = Utils::WStringToString(buf);
    ListView_GetItemText(hBanList_, sel, 2, buf, 256);
    g_banRemark = Utils::WStringToString(buf);

    g_banType = currentBanType_;
    g_isBanEdit = true;
    g_dialogResult = false;

    HWND hDlg = CreateBanDialogWindow(hwnd_, hInstance_);
    if (!hDlg) return;

    if (RunModalDialog(hDlg, hwnd_)) {
        if (g_banType == 0) {
            Database::Instance().UpdateWhitelist(g_banId, g_banIP, g_banRemark);
        } else if (g_banType == 1) {
            Database::Instance().UpdateBlacklist(g_banId, g_banIP, g_banRemark);
        } else if (g_banType == 3) {
            Database::Instance().UpdateNoAuthList(g_banId, g_banIP, g_banRemark);
        }
        RefreshBanList();
    }
}
