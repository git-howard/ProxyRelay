#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <windows.h>
#include <string>

// Windows 服务管理器 - 支持将 ProxyRelay 注册为系统服务
class ServiceManager {
public:
    static ServiceManager& Instance();
    
    // 服务名称和显示名称
    static constexpr const wchar_t* SERVICE_NAME = L"ProxyRelayService";
    static constexpr const wchar_t* SERVICE_DISPLAY = L"ProxyRelay 全局代理服务";
    static constexpr const wchar_t* SERVICE_DESC = L"ProxyRelay 二级代理管理 - 提供全局透明代理和流量路由服务";
    
    // 安装/卸载服务
    bool InstallService();
    bool UninstallService();
    
    // 启动/停止服务（通过 SCM）
    bool StartService();
    bool StopService();
    
    // 查询服务状态
    bool IsServiceInstalled();
    bool IsServiceRunning();
    
    // 服务入口点（由 SCM 调用）
    static void WINAPI ServiceMain(DWORD argc, LPWSTR* argv);
    static void WINAPI ServiceCtrlHandler(DWORD ctrlCode);
    
    // 服务运行主体
    void RunService();
    void StopServiceInternal();
    
private:
    ServiceManager() = default;
    ~ServiceManager() = default;
    
    // 报告服务状态
    void ReportServiceStatus(DWORD currentState, DWORD exitCode = NO_ERROR, DWORD waitHint = 0);
    
    SERVICE_STATUS serviceStatus_ = {};
    SERVICE_STATUS_HANDLE statusHandle_ = nullptr;
    HANDLE stopEvent_ = nullptr;
};
