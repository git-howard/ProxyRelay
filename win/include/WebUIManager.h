#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <wrl.h>
#include <string>
#include <memory>
#include <functional>
#include "WebView2.h"
#include "../libs/json.hpp"

class WebUIManager {
public:
    static WebUIManager& Instance();
    
    // 初始化 WebView2 控件并绑定到宿主窗口
    bool Initialize(HWND hWndParent, const std::wstring& uiPath = L"");
    
    // 窗口尺寸改变时调整 WebView2 大小
    void OnSize(int width, int height);
    
    // 向前端投递 JSON 消息或事件（线程安全，支持后台工作线程直接调用）
    void PostMessageToUI(const nlohmann::json& msg);
    
    // 供主窗口消息循环安全分发跨线程投递的 UI 消息
    void HandlePostUIMessage(const std::wstring& wJson);
    
    // 销毁并释放资源
    void Shutdown();
    
    bool IsInitialized() const { return initialized_; }

private:
    WebUIManager() = default;
    ~WebUIManager();

    // 注册前端请求路由处理
    void RegisterRoutes();
    
    // 分发处理前端发来的 RPC 请求
    nlohmann::json DispatchApi(const std::string& action, const nlohmann::json& params);

    // 各模块具体处理函数
    nlohmann::json HandleGetStatus();
    nlohmann::json HandleToggleService(bool start);
    
    nlohmann::json HandleGetPorts();
    nlohmann::json HandleSavePort(const nlohmann::json& p);
    nlohmann::json HandleDeletePort(int id);
    nlohmann::json HandleTogglePort(int id, bool enabled);
    nlohmann::json HandleTestPort(int id);
    nlohmann::json HandleRenamePortGroup(const std::string& oldName, const std::string& newName);
    
    nlohmann::json HandleGetRules();
    nlohmann::json HandleSaveRule(const nlohmann::json& r);
    nlohmann::json HandleDeleteRule(int id);
    nlohmann::json HandleToggleRule(int id, bool enabled);
    
    nlohmann::json HandleGetUsers();
    nlohmann::json HandleSaveUser(const nlohmann::json& u);
    nlohmann::json HandleDeleteUser(int id);
    nlohmann::json HandleToggleUser(int id, bool enabled);
    nlohmann::json HandleResetUserTraffic(int id);
    nlohmann::json HandleGetTrafficHistory(const std::string& mode, int count, int userId);
    nlohmann::json HandleGetNodeTrafficAnalysis(int portId, const std::string& mode, int year);
    
    nlohmann::json HandleGetConnections();
    nlohmann::json HandleCloseConnection(uint64_t connId);
    
    nlohmann::json HandleGetLogs(int limit);
    nlohmann::json HandleClearLogs();
    
    nlohmann::json HandleGetSettings();
    nlohmann::json HandleSaveSettings(const nlohmann::json& s);
    nlohmann::json HandleGetServiceStatus();
    nlohmann::json HandleControlService(const std::string& action);
    
    nlohmann::json HandleImportClashSub(const std::string& url, const std::string& name, const std::string& group = "", const std::string& includeFilter = "", const std::string& excludeFilter = "", int resetCycleDays = 0, const std::string& resetStartDate = "");
    nlohmann::json HandleGetSubscriptions();
    nlohmann::json HandleSaveSubscription(const nlohmann::json& p);
    nlohmann::json HandleUpdateSubscription(int id);
    nlohmann::json HandleDeleteSubscription(int id);
    nlohmann::json HandleRefreshPortNode(int portId);

    nlohmann::json HandleGenerateSelfSignedCert(const std::string& domains);
    nlohmann::json HandleLoadCustomCert(const nlohmann::json& params);
    nlohmann::json HandleResetDefaultCert();
    nlohmann::json HandleExportCert();

    nlohmann::json HandleGetChinaDirectSettings();
    nlohmann::json HandleSaveChinaDirectSettings(const nlohmann::json& params);
    nlohmann::json HandleUpdateChinaIpSubscription(const nlohmann::json& params);

    nlohmann::json HandleExportConfig();
    nlohmann::json HandleImportConfig(const nlohmann::json& params);

    HWND hWndParent_ = nullptr;
    bool initialized_ = false;
    std::wstring uiFolderPath_;
    
    Microsoft::WRL::ComPtr<ICoreWebView2Environment> webViewEnv_;
    Microsoft::WRL::ComPtr<ICoreWebView2Controller> webViewController_;
    Microsoft::WRL::ComPtr<ICoreWebView2> webView_;
    EventRegistrationToken webMessageToken_ = {};
};
