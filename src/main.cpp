#include "pch.h"
#include <gdiplus.h>
#include "MainWindow.h"
#include "ProxyServer.h"
#include "Database.h"
#include "TrafficMonitor.h"
#include "Utils.h"
#include <exception>
#include <string>
#include <fstream>
#include <shellapi.h>

#pragma comment(lib, "gdiplus.lib")
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

using namespace Gdiplus;

// 单实例互斥体名称
static const wchar_t* MUTEX_NAME = L"Global\\ProxyRelayMutex";
static HANDLE g_hMutex = nullptr;

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int) {
    // 检查单实例
    g_hMutex = CreateMutexW(nullptr, TRUE, MUTEX_NAME);
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        // 程序已在运行，尝试激活已有窗口
        HWND hExisting = FindWindowW(L"ProxyRelayWindow", nullptr);
        if (hExisting) {
            ShowWindow(hExisting, SW_RESTORE);
            SetForegroundWindow(hExisting);
        }
        if (g_hMutex) CloseHandle(g_hMutex);
        return 0;
    }
    
    try {
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
        
        // 清理过期日志文件
        std::string logDaysStr = Database::Instance().GetConfig("log_retention_days");
        int logDays = logDaysStr.empty() ? 30 : std::atoi(logDaysStr.c_str());
        if (logDays <= 0) logDays = 30;
        Utils::CleanOldLogs(logDays);
        
        // 创建主窗口
        if (!MainWindow::Instance().Create(hInstance)) {
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
        
        // 清理
        ProxyServer::Instance().Stop();
        TrafficMonitor::Instance().Stop();
        Database::Instance().Close();
        
        GdiplusShutdown(gdiplusToken);
        
        if (g_hMutex) CloseHandle(g_hMutex);
        
        WSACleanup();
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
