#include "ServiceManager.h"
#include "Database.h"
#include "ProxyServer.h"
#include "TrafficMonitor.h"
#include "XrayManager.h"
#include "Rules.h"
#include "SchannelSession.h"
#include "SharedStatusManager.h"
#include "Utils.h"
#include <string>
#include <vector>
#include <shellapi.h>
#include <aclapi.h>

#pragma comment(lib, "advapi32.lib")

// 检查当前是否以管理员权限运行
static bool IsElevated() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = nullptr;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(nullptr, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin != FALSE;
}

// 以管理员身份重新执行自身并携带指定参数，等待执行完成后返回
static bool RunElevated(const std::wstring& args) {
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    
    SHELLEXECUTEINFOW sei = {};
    sei.cbSize = sizeof(sei);
    sei.lpVerb = L"runas";
    sei.lpFile = exePath;
    sei.lpParameters = args.c_str();
    sei.nShow = SW_HIDE;
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    
    if (!ShellExecuteExW(&sei)) {
        return false; // 用户拒绝了 UAC 或其他错误
    }
    
    // 等待子进程完成
    if (sei.hProcess) {
        WaitForSingleObject(sei.hProcess, 30000); // 最多等 30 秒
        DWORD exitCode = 0;
        GetExitCodeProcess(sei.hProcess, &exitCode);
        CloseHandle(sei.hProcess);
        return exitCode == 0;
    }
    return true;
}

// 设置服务 DACL，允许交互式用户启停服务
static void GrantInteractiveAccess(SC_HANDLE hService) {
    // 获取当前安全描述符大小
    DWORD bytesNeeded = 0;
    QueryServiceObjectSecurity(hService, DACL_SECURITY_INFORMATION, nullptr, 0, &bytesNeeded);
    if (bytesNeeded == 0) return;
    
    // 分配并获取当前安全描述符
    std::vector<BYTE> sdBuf(bytesNeeded);
    PSECURITY_DESCRIPTOR pSD = (PSECURITY_DESCRIPTOR)sdBuf.data();
    if (!QueryServiceObjectSecurity(hService, DACL_SECURITY_INFORMATION, pSD, bytesNeeded, &bytesNeeded)) {
        return;
    }
    
    // 获取现有 DACL
    BOOL daclPresent = FALSE, daclDefaulted = FALSE;
    PACL pOldDacl = nullptr;
    GetSecurityDescriptorDacl(pSD, &daclPresent, &pOldDacl, &daclDefaulted);
    
    // 创建交互式用户 SID (S-1-5-4)
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    PSID pInteractiveSid = nullptr;
    if (!AllocateAndInitializeSid(&ntAuth, 1, SECURITY_INTERACTIVE_RID,
        0, 0, 0, 0, 0, 0, 0, &pInteractiveSid)) {
        return;
    }
    
    // 构建新的 ACE：允许交互式用户启动、停止、查询服务
    EXPLICIT_ACCESSW ea = {};
    ea.grfAccessPermissions = SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS | 
                              SERVICE_QUERY_CONFIG | SERVICE_INTERROGATE;
    ea.grfAccessMode = SET_ACCESS;
    ea.grfInheritance = NO_INHERITANCE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea.Trustee.ptstrName = (LPWSTR)pInteractiveSid;
    
    // 合并到现有 DACL
    PACL pNewDacl = nullptr;
    if (SetEntriesInAclW(1, &ea, pOldDacl, &pNewDacl) == ERROR_SUCCESS) {
        // 构建新的安全描述符
        SECURITY_DESCRIPTOR newSD;
        InitializeSecurityDescriptor(&newSD, SECURITY_DESCRIPTOR_REVISION);
        SetSecurityDescriptorDacl(&newSD, TRUE, pNewDacl, FALSE);
        
        SetServiceObjectSecurity(hService, DACL_SECURITY_INFORMATION, &newSD);
        LocalFree(pNewDacl);
    }
    
    FreeSid(pInteractiveSid);
}

ServiceManager& ServiceManager::Instance() {
    static ServiceManager instance;
    return instance;
}

bool ServiceManager::InstallService() {
    // 如果没有管理员权限，自动提权重新执行
    if (!IsElevated()) {
        Utils::Log("ServiceManager: 权限不足，尝试提权...");
        return RunElevated(L"--install");
    }
    
    // 获取当前可执行文件路径
    wchar_t exePath[MAX_PATH];
    if (!GetModuleFileNameW(nullptr, exePath, MAX_PATH)) {
        Utils::LogError("ServiceManager: 获取程序路径失败");
        return false;
    }
    
    // 构造服务启动命令（添加 --service 参数）
    std::wstring cmdLine = L"\"" + std::wstring(exePath) + L"\" --service";
    
    // 打开服务控制管理器
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!hSCM) {
        Utils::LogError("ServiceManager: 无法打开服务管理器, error=" + std::to_string(GetLastError()));
        return false;
    }
    
    // 创建服务
    SC_HANDLE hService = CreateServiceW(
        hSCM,
        SERVICE_NAME,
        SERVICE_DISPLAY,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,          // 开机自启
        SERVICE_ERROR_NORMAL,
        cmdLine.c_str(),
        nullptr,                     // 无负载排序组
        nullptr,                     // 无标签
        nullptr,                     // 无依赖
        nullptr,                     // LocalSystem 账户
        nullptr
    );
    
    if (!hService) {
        DWORD err = GetLastError();
        CloseServiceHandle(hSCM);
        if (err == ERROR_SERVICE_EXISTS) {
            Utils::Log("ServiceManager: 服务已存在");
            return true;
        }
        Utils::LogError("ServiceManager: 创建服务失败, error=" + std::to_string(err));
        return false;
    }
    
    // 设置服务描述
    SERVICE_DESCRIPTIONW desc;
    desc.lpDescription = (LPWSTR)SERVICE_DESC;
    ChangeServiceConfig2W(hService, SERVICE_CONFIG_DESCRIPTION, &desc);
    
    // 设置服务失败恢复策略（失败后自动重启）
    SC_ACTION actions[3] = {
        { SC_ACTION_RESTART, 5000 },  // 第一次失败: 5秒后重启
        { SC_ACTION_RESTART, 10000 }, // 第二次失败: 10秒后重启
        { SC_ACTION_RESTART, 30000 }  // 后续失败: 30秒后重启
    };
    SERVICE_FAILURE_ACTIONSW failActions = {};
    failActions.dwResetPeriod = 86400; // 24小时后重置计数
    failActions.cActions = 3;
    failActions.lpsaActions = actions;
    ChangeServiceConfig2W(hService, SERVICE_CONFIG_FAILURE_ACTIONS, &failActions);
    
    // 设置服务 DACL，允许交互式用户启停服务（无需每次 UAC）
    GrantInteractiveAccess(hService);
    
    // 安装后立即启动服务
    ::StartServiceW(hService, 0, nullptr);
    
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    
    Utils::Log("ServiceManager: 服务安装并启动成功");
    return true;
}

bool ServiceManager::UninstallService() {
    // 如果没有管理员权限，自动提权重新执行
    if (!IsElevated()) {
        Utils::Log("ServiceManager: 权限不足，尝试提权...");
        return RunElevated(L"--uninstall");
    }
    
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) {
        Utils::LogError("ServiceManager: 无法打开服务管理器");
        return false;
    }
    
    SC_HANDLE hService = OpenServiceW(hSCM, SERVICE_NAME, SERVICE_ALL_ACCESS);
    if (!hService) {
        CloseServiceHandle(hSCM);
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_DOES_NOT_EXIST) {
            Utils::Log("ServiceManager: 服务不存在");
            return true;
        }
        Utils::LogError("ServiceManager: 无法打开服务, error=" + std::to_string(err));
        return false;
    }
    
    // 先停止服务
    SERVICE_STATUS status;
    ControlService(hService, SERVICE_CONTROL_STOP, &status);
    
    // 等待停止
    for (int i = 0; i < 30; i++) {
        QueryServiceStatus(hService, &status);
        if (status.dwCurrentState == SERVICE_STOPPED) break;
        Sleep(1000);
    }
    
    // 删除服务
    BOOL result = DeleteService(hService);
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    
    if (result) {
        Utils::Log("ServiceManager: 服务卸载成功");
    } else {
        Utils::LogError("ServiceManager: 服务卸载失败, error=" + std::to_string(GetLastError()));
    }
    
    return result != FALSE;
}

bool ServiceManager::StartService() {
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hSCM) {
        if (!IsElevated()) return RunElevated(L"--start-service");
        return false;
    }
    
    SC_HANDLE hService = OpenServiceW(hSCM, SERVICE_NAME, SERVICE_START | SERVICE_QUERY_STATUS);
    if (!hService) {
        CloseServiceHandle(hSCM);
        if (!IsElevated()) return RunElevated(L"--start-service");
        return false;
    }
    
    BOOL result = ::StartServiceW(hService, 0, nullptr);
    if (!result && GetLastError() == ERROR_ACCESS_DENIED) {
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCM);
        if (!IsElevated()) return RunElevated(L"--start-service");
        return false;
    }
    
    // 等待服务启动完成
    if (result) {
        for (int i = 0; i < 30; i++) {
            SERVICE_STATUS status;
            QueryServiceStatus(hService, &status);
            if (status.dwCurrentState == SERVICE_RUNNING) break;
            Sleep(500);
        }
    }
    
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    
    return result != FALSE || GetLastError() == ERROR_SERVICE_ALREADY_RUNNING;
}

bool ServiceManager::StopService() {
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hSCM) {
        if (!IsElevated()) return RunElevated(L"--stop-service");
        return false;
    }
    
    SC_HANDLE hService = OpenServiceW(hSCM, SERVICE_NAME, SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!hService) {
        CloseServiceHandle(hSCM);
        if (!IsElevated()) return RunElevated(L"--stop-service");
        return false;
    }
    
    SERVICE_STATUS status;
    BOOL result = ControlService(hService, SERVICE_CONTROL_STOP, &status);
    if (!result && GetLastError() == ERROR_ACCESS_DENIED) {
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCM);
        if (!IsElevated()) return RunElevated(L"--stop-service");
        return false;
    }
    
    // 等待服务停止
    if (result) {
        for (int i = 0; i < 30; i++) {
            QueryServiceStatus(hService, &status);
            if (status.dwCurrentState == SERVICE_STOPPED) break;
            Sleep(500);
        }
    }
    
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    
    return result != FALSE;
}

bool ServiceManager::IsServiceInstalled() {
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hSCM) return false;
    
    SC_HANDLE hService = OpenServiceW(hSCM, SERVICE_NAME, SERVICE_QUERY_STATUS);
    bool installed = (hService != nullptr);
    if (hService) CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    
    return installed;
}

bool ServiceManager::IsServiceRunning() {
    // 1. 优先检查共享内存中是否有活跃的系统服务心跳（最快最准，跨权限与会话）
    if (SharedStatusManager::Instance().HasActiveHeartbeat()) {
        return true;
    }

    // 2. 检查 Windows 服务控制管理器状态
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hSCM) return false;
    
    SC_HANDLE hService = OpenServiceW(hSCM, SERVICE_NAME, SERVICE_QUERY_STATUS);
    if (!hService) {
        CloseServiceHandle(hSCM);
        return false;
    }
    
    SERVICE_STATUS status;
    QueryServiceStatus(hService, &status);
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    
    return status.dwCurrentState == SERVICE_RUNNING || status.dwCurrentState == SERVICE_START_PENDING;
}

void WINAPI ServiceManager::ServiceMain(DWORD argc, LPWSTR* argv) {
    ServiceManager::Instance().RunService();
}

void WINAPI ServiceManager::ServiceCtrlHandler(DWORD ctrlCode) {
    switch (ctrlCode) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        ServiceManager::Instance().ReportServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, 5000);
        ServiceManager::Instance().StopServiceInternal();
        break;
        
    case SERVICE_CONTROL_INTERROGATE:
        // 返回当前状态
        break;
    }
}

void ServiceManager::RunService() {
    // 注册控制处理函数
    statusHandle_ = RegisterServiceCtrlHandlerW(SERVICE_NAME, ServiceCtrlHandler);
    if (!statusHandle_) {
        Utils::LogError("ServiceManager: RegisterServiceCtrlHandler 失败");
        return;
    }
    
    // 初始化服务状态
    serviceStatus_.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    serviceStatus_.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    
    ReportServiceStatus(SERVICE_START_PENDING, NO_ERROR, 10000);
    
    // 创建停止事件
    stopEvent_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!stopEvent_) {
        ReportServiceStatus(SERVICE_STOPPED, GetLastError());
        return;
    }
    
    // 初始化 Winsock
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    
    // 切换工作目录到可执行文件所在目录
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    std::wstring exeDir(exePath);
    size_t pos = exeDir.find_last_of(L"\\/");
    if (pos != std::wstring::npos) {
        exeDir = exeDir.substr(0, pos);
        SetCurrentDirectoryW(exeDir.c_str());
    }
    
    // 初始化数据库
    if (!Database::Instance().Initialize("proxy.db")) {
        Utils::LogError("ServiceManager: 数据库初始化失败");
        ReportServiceStatus(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR);
        CloseHandle(stopEvent_);
        return;
    }
    
    // 初始化 TLS 证书凭据环境
    SchannelSession::InitializeCredentials();
    
    // 初始化路由规则
    RuleManager::Instance().Initialize();
    
    // 启动代理服务器
    ProxyServer::Instance().Start();
    TrafficMonitor::Instance().Start();
    
    Utils::Log("ServiceManager: 服务启动完成");
    ReportServiceStatus(SERVICE_RUNNING);
    
    // 监听停止事件和重载事件（支持热重载分流规则与代理配置，无需重启服务）
    HANDLE reloadEvent = SharedStatusManager::Instance().GetReloadEventHandle();
    HANDLE waitHandles[2] = { stopEvent_, reloadEvent };
    DWORD handleCount = reloadEvent ? 2 : 1;
    
    int lastDataVersion = Database::Instance().GetDataVersion();
    
    while (true) {
        DWORD waitRes = WaitForMultipleObjects(handleCount, waitHandles, FALSE, 1000);
        if (waitRes == WAIT_OBJECT_0) {
            break; // 收到服务停止信号
        }
        
        bool needReloadRules = false;
        bool needReloadPorts = false;
        SharedStatusManager::Instance().CheckAndClearReloadRequest(needReloadRules, needReloadPorts);
        
        // 检查 SQLite 数据版本（检测其他进程或外部工具直接写入数据库的情况）
        int curDataVersion = Database::Instance().GetDataVersion();
        if (curDataVersion != 0 && curDataVersion != lastDataVersion) {
            lastDataVersion = curDataVersion;
            needReloadRules = true;
        }
        
        if (needReloadRules) {
            Utils::Log("ServiceManager: 检测到分流规则更新，正在实时重新加载分流规则...");
            RuleManager::Instance().ReloadRoutingRules();
        }
        if (needReloadPorts) {
            Utils::Log("ServiceManager: 检测到代理端口更新，正在实时重新加载端口配置...");
            ProxyServer::Instance().ReloadPorts();
        }
    }
    
    // 清理
    Utils::Log("ServiceManager: 服务正在停止...");
    ProxyServer::Instance().Stop();
    TrafficMonitor::Instance().Stop();
    Database::Instance().Close();
    
    WSACleanup();
    CloseHandle(stopEvent_);
    stopEvent_ = nullptr;
    
    ReportServiceStatus(SERVICE_STOPPED);
    Utils::Log("ServiceManager: 服务已停止");
}

void ServiceManager::StopServiceInternal() {
    if (stopEvent_) {
        SetEvent(stopEvent_);
    }
}

void ServiceManager::ReportServiceStatus(DWORD currentState, DWORD exitCode, DWORD waitHint) {
    static DWORD checkPoint = 1;
    
    serviceStatus_.dwCurrentState = currentState;
    serviceStatus_.dwWin32ExitCode = exitCode;
    serviceStatus_.dwWaitHint = waitHint;
    
    if (currentState == SERVICE_START_PENDING) {
        serviceStatus_.dwControlsAccepted = 0;
    } else {
        serviceStatus_.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    }
    
    if (currentState == SERVICE_RUNNING || currentState == SERVICE_STOPPED) {
        serviceStatus_.dwCheckPoint = 0;
    } else {
        serviceStatus_.dwCheckPoint = checkPoint++;
    }
    
    SetServiceStatus(statusHandle_, &serviceStatus_);
}
