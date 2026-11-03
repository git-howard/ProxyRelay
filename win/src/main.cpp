#include "pch.h"
#include <gdiplus.h>
#include "MainWindow.h"
#include "ProxyServer.h"
#include "XrayManager.h"
#include "ClashManager.h"
#include "Database.h"
#include "TrafficMonitor.h"
#include "ServiceManager.h"
#include "Rules.h"
#include "SchannelSession.h"
#include "Utils.h"
#include <exception>
#include <string>
#include <fstream>
#include <filesystem>
#include <shellapi.h>

#pragma comment(lib, "gdiplus.lib")
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

using namespace Gdiplus;

// 单实例互斥体名称
static const wchar_t* MUTEX_NAME = L"Global\\ProxyRelayMutex";
static HANDLE g_hMutex = nullptr;

// 解析命令行参数
static std::wstring GetCommandLineArg() {
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    std::wstring arg;
    if (argv && argc > 1) {
        arg = argv[1];
    }
    if (argv) LocalFree(argv);
    return arg;
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int) {
    // 切换工作目录到 exe 所在目录（确保开机自启动时路径正确）
    {
        wchar_t exePathBuf[MAX_PATH] = {};
        GetModuleFileNameW(nullptr, exePathBuf, MAX_PATH);
        std::filesystem::path exeDir = std::filesystem::path(exePathBuf).parent_path();
        SetCurrentDirectoryW(exeDir.c_str());
    }
    
    // 解析命令行参数
    std::wstring cmdArg = GetCommandLineArg();
    
    // Windows 服务模式入口
    if (cmdArg == L"--service") {
        SERVICE_TABLE_ENTRYW serviceTable[] = {
            { (LPWSTR)ServiceManager::SERVICE_NAME, ServiceManager::ServiceMain },
            { nullptr, nullptr }
        };
        StartServiceCtrlDispatcherW(serviceTable);
        return 0;
    }
    
    // 服务安装/卸载/启停命令行工具
    if (cmdArg == L"--install" || cmdArg == L"--install-service") {
        return ServiceManager::Instance().InstallService() ? 0 : 1;
    }
    if (cmdArg == L"--uninstall" || cmdArg == L"--uninstall-service") {
        return ServiceManager::Instance().UninstallService() ? 0 : 1;
    }
    if (cmdArg == L"--start-service") {
        return ServiceManager::Instance().StartService() ? 0 : 1;
    }
    if (cmdArg == L"--stop-service") {
        return ServiceManager::Instance().StopService() ? 0 : 1;
    }
    
    bool startMinimized = (cmdArg == L"--minimized");
    
    // 默认: GUI 模式
    // 检查单实例：使用带 NULL DACL 的安全性属性与 Local 命名空间，确保非管理员与管理员均可准确互斥
    SECURITY_DESCRIPTOR sd = {};
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&sd, TRUE, nullptr, FALSE);
    SECURITY_ATTRIBUTES sa = {};
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = &sd;
    sa.bInheritHandle = FALSE;

    static const wchar_t* GUI_MUTEX_NAME = L"Local\\ProxyRelay_GUI_SingleInstance_Mutex";
    g_hMutex = CreateMutexW(&sa, TRUE, GUI_MUTEX_NAME);
    DWORD lastErr = GetLastError();
    if (g_hMutex == nullptr || lastErr == ERROR_ALREADY_EXISTS || lastErr == ERROR_ACCESS_DENIED) {
        // 程序已在运行，尝试唤醒并置顶已有窗口
        HWND hExisting = FindWindowW(L"ProxyRelayWindow", nullptr);
        if (hExisting) {
            DWORD curThreadId = GetCurrentThreadId();
            DWORD targetThreadId = GetWindowThreadProcessId(hExisting, nullptr);
            AttachThreadInput(curThreadId, targetThreadId, TRUE);
            ShowWindow(hExisting, SW_SHOW);
            ShowWindow(hExisting, SW_RESTORE);
            SetForegroundWindow(hExisting);
            AttachThreadInput(curThreadId, targetThreadId, FALSE);
            PostMessageW(hExisting, WM_COMMAND, ID_TRAY_SHOW, 0);
        }
        if (g_hMutex) CloseHandle(g_hMutex);
        return 0;
    }
    
    try {
        // 初始化 COM (WebView2 需要 STA 模型)
        CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

        // 初始化Winsock
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);

        // 初始化GDI+
        GdiplusStartupInput gdiplusStartupInput;
        ULONG_PTR gdiplusToken;
        Status status = GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, nullptr);
        if (status != Ok) {
            MessageBoxW(nullptr, L"GDI+ 初始化失败", L"错误", MB_OK | MB_ICONERROR);
            if (g_hMutex) CloseHandle(g_hMutex);
            return 1;
        }
        
        // 初始化数据库
        if (!Database::Instance().Initialize("proxy.db")) {
            MessageBoxW(nullptr, L"数据库初始化失败\n请检查是否有写入权限", L"错误", MB_OK | MB_ICONERROR);
            GdiplusShutdown(gdiplusToken);
            if (g_hMutex) CloseHandle(g_hMutex);
            return 1;
        }

        // 初始化 TLS 证书与凭据（确保偏好设置与代理核心第一时间拥有有效凭据）
        SchannelSession::InitializeCredentials();

        // 初始化分流规则管理器（确保无论何种运行模式分流规则均完成加载）
        RuleManager::Instance().Initialize();

        // 前置初始化内核管理器（确保后台测速与出站代理无论服务是否运行均能找到可执行路径）
        XrayManager::Instance().Initialize();
        ClashManager::Instance().Initialize();
        
        // 清理过期日志文件
        std::string logDaysStr = Database::Instance().GetConfig("log_retention_days");
        int logDays = logDaysStr.empty() ? 30 : std::atoi(logDaysStr.c_str());
        if (logDays <= 0) logDays = 30;
        Utils::CleanOldLogs(logDays);
        
        // 创建主窗口
        if (!MainWindow::Instance().Create(hInstance, startMinimized)) {
            DWORD err = GetLastError();
            std::wstring msg = L"窗口创建失败\n错误代码: " + std::to_wstring(err);
            MessageBoxW(nullptr, msg.c_str(), L"错误", MB_OK | MB_ICONERROR);
            Database::Instance().Close();
            GdiplusShutdown(gdiplusToken);
            if (g_hMutex) CloseHandle(g_hMutex);
            return 1;
        }
        
        // 运行消息循环
        int result = MainWindow::Instance().Run();
        
        // 清理: 仅当独立核心运行时，退出才停止核心代理服务
        // 若后台系统服务正在运行，控制台退出绝不干扰系统服务的稳定运行
        if (!MainWindow::Instance().IsConsoleOnlyMode()) {
            ProxyServer::Instance().Stop();
            TrafficMonitor::Instance().Stop();
        }
        Database::Instance().Close();
        
        GdiplusShutdown(gdiplusToken);
        
        if (g_hMutex) CloseHandle(g_hMutex);
        
        WSACleanup();
        CoUninitialize();
        return result;
    }
    catch (const std::exception& e) {
        std::string msg = "Exception: ";
        msg += e.what();
        MessageBoxA(nullptr, msg.c_str(), "错误", MB_OK | MB_ICONERROR);
        if (g_hMutex) CloseHandle(g_hMutex);
        return 1;
    }
    catch (...) {
        MessageBoxW(nullptr, L"程序发生未知异常", L"错误", MB_OK | MB_ICONERROR);
        if (g_hMutex) CloseHandle(g_hMutex);
        return 1;
    }
}
