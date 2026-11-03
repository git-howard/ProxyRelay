#include "pch.h"
#include "MainWindow.h"
#include "WebUIManager.h"
#include "ProxyServer.h"
#include "Database.h"
#include "TrafficMonitor.h"
#include "ConnectionLogger.h"
#include "ServiceManager.h"
#include "SharedStatusManager.h"
#include "ClashManager.h"
#include "Utils.h"
#include <dwmapi.h>
#include <shellapi.h>

#pragma comment(lib, "dwmapi.lib")

static const wchar_t* WINDOW_CLASS_NAME = L"ProxyRelayWindow";

MainWindow& MainWindow::Instance() {
    static MainWindow instance;
    return instance;
}

MainWindow::~MainWindow() {
    RemoveTrayIcon();
}

bool MainWindow::Create(HINSTANCE hInstance, bool startMinimized) {
    hInstance_ = hInstance;
    startMinimized_ = startMinimized;

    WNDCLASSEXW wcex = {};
    wcex.cbSize = sizeof(WNDCLASSEXW);
    wcex.style = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc = MainWindow::WndProc;
    wcex.hInstance = hInstance;
    wcex.hIcon = (HICON)LoadImageW(hInstance, MAKEINTRESOURCEW(1), IMAGE_ICON, 32, 32, LR_DEFAULTCOLOR);
    if (!wcex.hIcon) wcex.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
    wcex.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground = CreateSolidBrush(RGB(8, 11, 17)); // #080B11
    wcex.lpszClassName = WINDOW_CLASS_NAME;
    wcex.hIconSm = (HICON)LoadImageW(hInstance, MAKEINTRESOURCEW(1), IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR);

    RegisterClassExW(&wcex);

    // 默认居中尺寸 1160 x 760
    int screenW = GetSystemMetrics(SM_CXSCREEN);
    int screenH = GetSystemMetrics(SM_CYSCREEN);
    int winW = 1160;
    int winH = 760;
    int posX = (screenW - winW) / 2;
    int posY = (screenH - winH) / 2;

    hwnd_ = CreateWindowExW(
        0,
        WINDOW_CLASS_NAME,
        L"ProxyRelay 二级代理管理器",
        WS_OVERLAPPEDWINDOW,
        posX, posY, winW, winH,
        nullptr, nullptr, hInstance, this
    );

    if (!hwnd_) return false;

    // 开启 Win11 原生沉浸式暗黑标题栏
    BOOL darkMode = TRUE;
    DwmSetWindowAttribute(hwnd_, DWMWA_USE_IMMERSIVE_DARK_MODE, &darkMode, sizeof(darkMode));

    // 创建系统托盘图标
    CreateTrayIcon();

    // 绑定连接日志实时推送至前端
    ConnectionLogger::Instance().SetUICallback([](const ConnectionLogEntry& entry) {
        nlohmann::json logObj = {
            {"event", "log_entry"},
            {"data", {
                {"timestamp", entry.timestamp},
                {"username", entry.username},
                {"clientIP", entry.clientIP},
                {"inboundType", entry.inboundType.empty() ? "HTTP" : entry.inboundType},
                {"targetHost", entry.targetHost},
                {"targetPort", entry.targetPort},
                {"action", entry.action},
                {"proxyDesc", entry.proxyDesc}
            }}
        };
        WebUIManager::Instance().PostMessageToUI(logObj);
    });

    // 初始化现代 WebView2 界面
    WebUIManager::Instance().Initialize(hwnd_, L"ui");

    // 启动 1 秒心跳定时器
    SetTimer(hwnd_, IDT_REFRESH, 1000, nullptr);

    // 启动后台代理节点可用性与延时定期检测 (每分钟自动刷新)
    ProxyServer::Instance().StartProxyChecker();

    // 启动 Clash 订阅自动定时更新 (每天从订阅网站获取最新流量与节点)
    ClashManager::Instance().StartAutoUpdate();

    // 检查是否已作为 Windows 服务在后台运行
    bool isServiceRunning = ServiceManager::Instance().IsServiceRunning();
    if (isServiceRunning) {
        // 作为服务启动后，点击程序仅打开控制台，不要在 GUI 进程中重复启动整个代理网络核心
        isConsoleOnlyMode_ = true;
        Utils::Log("ServiceManager: Windows 服务已在后台运行，GUI 仅作为控制台模式打开");
    } else {
        isConsoleOnlyMode_ = false;
        // 根据上次运行状态自动恢复代理服务
        std::string lastState = Database::Instance().GetConfig("last_service_state", "0");
        if (lastState == "1") {
            ProxyServer::Instance().Start();
            TrafficMonitor::Instance().Start();
        }
    }

    if (!startMinimized) {
        ShowWindow(hwnd_, SW_SHOW);
        UpdateWindow(hwnd_);
    }

    return true;
}

int MainWindow::Run() {
    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return (int)msg.wParam;
}

LRESULT CALLBACK MainWindow::WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    MainWindow* pThis = nullptr;
    if (msg == WM_NCCREATE) {
        auto cs = reinterpret_cast<CREATESTRUCTW*>(lParam);
        pThis = reinterpret_cast<MainWindow*>(cs->lpCreateParams);
        if (pThis) {
            pThis->hwnd_ = hwnd;
        }
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(pThis));
    } else {
        pThis = reinterpret_cast<MainWindow*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    }

    if (pThis) {
        return pThis->HandleMessage(hwnd, msg, wParam, lParam);
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

LRESULT MainWindow::HandleMessage(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_NCCREATE:
        return DefWindowProcW(hwnd, msg, wParam, lParam);

    case WM_SIZE: {
        int width = LOWORD(lParam);
        int height = HIWORD(lParam);
        WebUIManager::Instance().OnSize(width, height);
        return 0;
    }

    case WM_TIMER: {
        if (wParam == IDT_REFRESH) {
            bool isService = ServiceManager::Instance().IsServiceRunning();
            if (isService) {
                isConsoleOnlyMode_ = true;
            }
            bool isRunning = isService || ProxyServer::Instance().IsRunning();

            int activeConns = isService ? 0 : ProxyServer::Instance().GetActiveConnections();
            auto curData = TrafficMonitor::Instance().GetCurrentData();
            int64_t uploadSpeed = curData.uploadSpeed;
            int64_t downloadSpeed = curData.downloadSpeed;
            int64_t totalUpload = curData.totalUpload;
            int64_t totalDownload = curData.totalDownload;

            // 优先从共享内存读取 Windows 服务的实时状态与速率
            bool sharedRunning = false;
            int sharedActiveConns = 0;
            int64_t sharedUpSpeed = 0, sharedDownSpeed = 0, sharedTotalUp = 0, sharedTotalDown = 0;
            int64_t sharedUptime = 0;
            bool sharedOk = SharedStatusManager::Instance().ReadStatus(sharedRunning, sharedActiveConns, sharedUpSpeed, sharedDownSpeed, sharedTotalUp, sharedTotalDown, &sharedUptime);
            if (sharedOk) {
                isRunning = sharedRunning;
                activeConns = sharedActiveConns;
                uploadSpeed = sharedUpSpeed;
                downloadSpeed = sharedDownSpeed;
                totalUpload = sharedTotalUp;
                totalDownload = sharedTotalDown;
            } else if (totalUpload == 0 && totalDownload == 0) {
                Database::Instance().GetTotalTraffic(totalUpload, totalDownload);
            }

            int64_t uptimeSec = sharedOk ? sharedUptime : (isRunning ? ProxyServer::Instance().GetUptime() : 0);

            // 每秒向 Web 前端主动推送实时速度和网络数据
            nlohmann::json ticker = {
                {"event", "ticker"},
                {"data", {
                    {"isRunning", isRunning},
                    {"isServiceMode", isService || isConsoleOnlyMode_},
                    {"activeConnections", activeConns},
                    {"uploadSpeed", uploadSpeed},
                    {"downloadSpeed", downloadSpeed},
                    {"totalUpload", totalUpload},
                    {"totalDownload", totalDownload},
                    {"uptime", uptimeSec},
                    {"uptimeSeconds", uptimeSec},
                    {"uptime_seconds", uptimeSec}
                }}
            };
            WebUIManager::Instance().PostMessageToUI(ticker);
        }
        return 0;
    }

    case WM_POST_UI_MESSAGE: {
        std::wstring* pStr = reinterpret_cast<std::wstring*>(lParam);
        if (pStr) {
            WebUIManager::Instance().HandlePostUIMessage(*pStr);
            delete pStr;
        }
        return 0;
    }

    case WM_TRAYICON: {
        if (lParam == WM_LBUTTONUP) {
            RestoreFromTray();
        } else if (lParam == WM_RBUTTONUP) {
            ShowTrayMenu();
        }
        return 0;
    }

    case WM_COMMAND: {
        UINT id = LOWORD(wParam);
        if (id == ID_TRAY_SHOW) {
            RestoreFromTray();
        } else if (id == ID_TRAY_AUTOSTART) {
            SetAutoStart(!IsAutoStartEnabled());
        } else if (id == ID_TRAY_EXIT) {
            RemoveTrayIcon();
            DestroyWindow(hwnd);
        }
        return 0;
    }

    case WM_CLOSE: {
        std::string closeToTray = Database::Instance().GetConfig("close_to_tray", "1");
        if (closeToTray == "1") {
            MinimizeToTray();
            return 0;
        }
        DestroyWindow(hwnd);
        return 0;
    }

    case WM_DESTROY: {
        KillTimer(hwnd, IDT_REFRESH);
        RemoveTrayIcon();
        ProxyServer::Instance().StopProxyChecker();
        WebUIManager::Instance().Shutdown();
        PostQuitMessage(0);
        return 0;
    }
    }

    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

void MainWindow::CreateTrayIcon() {
    if (trayIconCreated_) return;

    nid_.cbSize = sizeof(NOTIFYICONDATAW);
    nid_.hWnd = hwnd_;
    nid_.uID = 1;
    nid_.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    nid_.uCallbackMessage = WM_TRAYICON;
    nid_.hIcon = (HICON)LoadImageW(hInstance_, MAKEINTRESOURCEW(1), IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR);
    if (!nid_.hIcon) nid_.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
    if (isConsoleOnlyMode_) {
        wcscpy_s(nid_.szTip, L"ProxyRelay - 控制台 (系统服务运行中)");
    } else {
        wcscpy_s(nid_.szTip, L"ProxyRelay - 二级代理管理系统");
    }

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
    AppendMenuW(hMenu, MF_STRING, ID_TRAY_SHOW, L"打开控制台");
    AppendMenuW(hMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hMenu, MF_STRING | (IsAutoStartEnabled() ? MF_CHECKED : 0), ID_TRAY_AUTOSTART, L"开机自启动");
    AppendMenuW(hMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hMenu, MF_STRING, ID_TRAY_EXIT, L"退出程序");

    SetForegroundWindow(hwnd_);
    UINT cmd = TrackPopupMenu(hMenu, TPM_RETURNCMD | TPM_NONOTIFY, pt.x, pt.y, 0, hwnd_, nullptr);
    DestroyMenu(hMenu);

    if (cmd == ID_TRAY_SHOW) {
        RestoreFromTray();
    } else if (cmd == ID_TRAY_AUTOSTART) {
        SetAutoStart(!IsAutoStartEnabled());
    } else if (cmd == ID_TRAY_EXIT) {
        RemoveTrayIcon();
        DestroyWindow(hwnd_);
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
    bool enabled = (RegQueryValueExW(hKey, L"ProxyRelay", nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS);
    RegCloseKey(hKey);
    return enabled;
}

void MainWindow::SetAutoStart(bool enable) {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                      0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        if (enable) {
            wchar_t exePath[MAX_PATH];
            GetModuleFileNameW(nullptr, exePath, MAX_PATH);
            std::wstring val = L"\"" + std::wstring(exePath) + L"\" --minimized";
            RegSetValueExW(hKey, L"ProxyRelay", 0, REG_SZ,
                          (const BYTE*)val.c_str(), (DWORD)((val.length() + 1) * sizeof(wchar_t)));
        } else {
            RegDeleteValueW(hKey, L"ProxyRelay");
        }
        RegCloseKey(hKey);
    }
}

// 兼容性占位方法
void MainWindow::UpdateStatus() {}
void MainWindow::RefreshUserList() {}
void MainWindow::RefreshPortList() {}
void MainWindow::RefreshTrafficGraph() {}
void MainWindow::AddLogEntry(const ConnectionLogEntry&) {}
