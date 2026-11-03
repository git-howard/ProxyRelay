#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <shellapi.h>
#include <string>

struct ConnectionLogEntry;

// 定时器 ID
#define IDT_REFRESH         6001

// 自定义消息与托盘
#define WM_TRAYICON         (WM_USER + 101)
#define WM_POST_UI_MESSAGE  (WM_USER + 102)

#define ID_TRAY_SHOW        7001
#define ID_TRAY_AUTOSTART   7002
#define ID_TRAY_EXIT        7003

class MainWindow {
public:
    static MainWindow& Instance();
    
    bool Create(HINSTANCE hInstance, bool startMinimized = false);
    int Run();
    
    HWND GetHandle() const { return hwnd_; }
    bool IsConsoleOnlyMode() const { return isConsoleOnlyMode_; }
    void SetConsoleOnlyMode(bool consoleOnly) { isConsoleOnlyMode_ = consoleOnly; }
    void UpdateStatus();
    void RefreshUserList();
    void RefreshPortList();
    void RefreshTrafficGraph();
    void AddLogEntry(const ConnectionLogEntry& entry);
    
private:
    MainWindow() = default;
    ~MainWindow();
    
    static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    LRESULT HandleMessage(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    
    // 托盘相关
    void CreateTrayIcon();
    void RemoveTrayIcon();
    void ShowTrayMenu();
    void MinimizeToTray();
    void RestoreFromTray();
    
    // 开机自启
    bool IsAutoStartEnabled();
    void SetAutoStart(bool enable);
    
    HWND hwnd_ = nullptr;
    HINSTANCE hInstance_ = nullptr;
    bool startMinimized_ = false;
    bool isConsoleOnlyMode_ = false;
    
    NOTIFYICONDATAW nid_ = {};
    bool trayIconCreated_ = false;
};
