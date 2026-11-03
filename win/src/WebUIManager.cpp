#include "WebUIManager.h"
#include "MainWindow.h"
#include "ProxyServer.h"
#include "Database.h"
#include "TrafficMonitor.h"
#include "RealtimeConnectionManager.h"
#include "ConnectionLogger.h"
#include "Rules.h"
#include "UserManager.h"
#include "ServiceManager.h"
#include "ClashManager.h"
#include "XrayManager.h"
#include "Utils.h"
#include "Version.h"
#include "SchannelSession.h"
#include "SharedStatusManager.h"
#include <wininet.h>
#include <filesystem>
#include <chrono>
#include <thread>
#include <regex>

#pragma comment(lib, "wininet.lib")

using namespace Microsoft::WRL;

WebUIManager& WebUIManager::Instance() {
    static WebUIManager instance;
    return instance;
}

WebUIManager::~WebUIManager() {
    Shutdown();
}

void WebUIManager::Shutdown() {
    if (webMessageToken_.value != 0 && webView_) {
        webView_->remove_WebMessageReceived(webMessageToken_);
        webMessageToken_.value = 0;
    }
    if (webViewController_) {
        webViewController_->Close();
        webViewController_ = nullptr;
    }
    webView_ = nullptr;
    webViewEnv_ = nullptr;
    initialized_ = false;
}

void WebUIManager::OnSize(int width, int height) {
    if (webViewController_) {
        RECT bounds = { 0, 0, width, height };
        webViewController_->put_Bounds(bounds);
    }
}

void WebUIManager::HandlePostUIMessage(const std::wstring& wJson) {
    if (webView_) {
        webView_->PostWebMessageAsJson(wJson.c_str());
    }
}

void WebUIManager::PostMessageToUI(const nlohmann::json& msg) {
    if (!webView_) return;
    std::string jsonStr = msg.dump();
    std::wstring wJson = Utils::StringToWString(jsonStr);

    DWORD uiThreadId = hWndParent_ ? GetWindowThreadProcessId(hWndParent_, nullptr) : 0;
    if (uiThreadId == 0 || GetCurrentThreadId() == uiThreadId) {
        webView_->PostWebMessageAsJson(wJson.c_str());
    } else {
        std::wstring* pStr = new std::wstring(std::move(wJson));
        if (!PostMessageW(hWndParent_, WM_POST_UI_MESSAGE, 0, reinterpret_cast<LPARAM>(pStr))) {
            delete pStr;
        }
    }
}

bool WebUIManager::Initialize(HWND hWndParent, const std::wstring& uiPath) {
    hWndParent_ = hWndParent;
    uiFolderPath_ = uiPath.empty() ? L"ui" : uiPath;

    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    std::filesystem::path exeDir = std::filesystem::path(exePath).parent_path();
    std::filesystem::path userDataPath = exeDir / "data" / "webview2";
    std::filesystem::create_directories(userDataPath);

    HRESULT hr = CreateCoreWebView2EnvironmentWithOptions(
        nullptr,
        userDataPath.c_str(),
        nullptr,
        Callback<ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler>(
            [this, exeDir](HRESULT result, ICoreWebView2Environment* env) -> HRESULT {
                if (FAILED(result) || !env) {
                    MessageBoxW(hWndParent_,
                        L"未检测到 Microsoft Edge WebView2 运行时环境。\n"
                        L"为获得最佳现代化界面体验，请确保系统中已安装 Edge WebView2 Runtime。",
                        L"ProxyRelay - 提示", MB_OK | MB_ICONWARNING);
                    return result;
                }
                webViewEnv_ = env;
                
                env->CreateCoreWebView2Controller(
                    hWndParent_,
                    Callback<ICoreWebView2CreateCoreWebView2ControllerCompletedHandler>(
                        [this, exeDir](HRESULT result, ICoreWebView2Controller* controller) -> HRESULT {
                            if (FAILED(result) || !controller) return result;
                            webViewController_ = controller;
                            controller->get_CoreWebView2(&webView_);

                            // 沉浸式暗色背景，避免启动白屏闪烁
                            COREWEBVIEW2_COLOR darkBg = { 255, 11, 15, 25 };
                            ComPtr<ICoreWebView2Controller2> ctrl2;
                            if (SUCCEEDED(controller->QueryInterface(IID_PPV_ARGS(&ctrl2))) && ctrl2) {
                                ctrl2->put_DefaultBackgroundColor(darkBg);
                            }

                            // 现代化配置：禁用原生右键菜单与网页状态栏
                            ComPtr<ICoreWebView2Settings> settings;
                            if (SUCCEEDED(webView_->get_Settings(&settings)) && settings) {
                                settings->put_AreDefaultContextMenusEnabled(FALSE);
                                settings->put_IsStatusBarEnabled(FALSE);
                                settings->put_IsZoomControlEnabled(FALSE);
                            }

                            // 映射虚拟域名 https://proxyrelay.local -> UI 目录
                            std::filesystem::path absUiPath = exeDir / uiFolderPath_;
                            std::wstring uiFullPath = absUiPath.wstring();
                            
                            ComPtr<ICoreWebView2_3> webView3;
                            if (SUCCEEDED(webView_->QueryInterface(IID_PPV_ARGS(&webView3))) && webView3) {
                                webView3->SetVirtualHostNameToFolderMapping(
                                    L"proxyrelay.local",
                                    uiFullPath.c_str(),
                                    COREWEBVIEW2_HOST_RESOURCE_ACCESS_KIND_ALLOW
                                );
                                webView_->Navigate(L"https://proxyrelay.local/index.html");
                            } else {
                                std::wstring localUrl = L"file:///" + uiFullPath + L"/index.html";
                                webView_->Navigate(localUrl.c_str());
                            }

                            // 注册消息接收
                            RegisterRoutes();

                            // 调整尺寸并显示
                            RECT rc;
                            GetClientRect(hWndParent_, &rc);
                            OnSize(rc.right - rc.left, rc.bottom - rc.top);
                            webViewController_->put_IsVisible(TRUE);
                            initialized_ = true;
                            return S_OK;
                        }).Get());
                return S_OK;
            }).Get());

    return SUCCEEDED(hr);
}

void WebUIManager::RegisterRoutes() {
    if (!webView_) return;

    webView_->add_WebMessageReceived(
        Callback<ICoreWebView2WebMessageReceivedEventHandler>(
            [this](ICoreWebView2* sender, ICoreWebView2WebMessageReceivedEventArgs* args) -> HRESULT {
                LPWSTR msgRaw = nullptr;
                if (SUCCEEDED(args->get_WebMessageAsJson(&msgRaw)) && msgRaw) {
                    std::wstring rawStr(msgRaw);
                    CoTaskMemFree(msgRaw);

                    int reqId = 0;
                    std::string action;
                    try {
                        std::string jsonStr = Utils::WStringToString(rawStr);
                        auto req = nlohmann::json::parse(jsonStr);
                        
                        reqId = req.value("id", 0);
                        action = req.value("action", "");
                        nlohmann::json params = req.value("data", nlohmann::json::object());

                        // 耗时网络操作（测速、订阅在线拉取与更新、Clash 节点手动更新、国内IP订阅更新）交由后台线程，避免阻塞 UI 交互
                        if (action == "test_port" || action == "import_clash_sub" || action == "update_subscription" || action == "refresh_clash_node" || action == "update_china_ip_subscription") {
                            std::thread([this, reqId, action, params]() {
                                try {
                                    nlohmann::json result = DispatchApi(action, params);
                                    nlohmann::json resp;
                                    resp["id"] = reqId;
                                    resp["action"] = action;
                                    resp["success"] = true;
                                    resp["data"] = result;
                                    PostMessageToUI(resp);
                                } catch (const std::exception& e) {
                                    nlohmann::json errResp;
                                    errResp["id"] = reqId;
                                    errResp["action"] = action;
                                    errResp["success"] = false;
                                    errResp["error"] = e.what();
                                    PostMessageToUI(errResp);
                                }
                            }).detach();
                        } else {
                            // 所有基础数据加载与常规控制（耗时 < 1ms），在主 UI 线程同步完成并立即响应前端 Promise
                            nlohmann::json result = DispatchApi(action, params);
                            
                            nlohmann::json resp;
                            resp["id"] = reqId;
                            resp["action"] = action;
                            resp["success"] = true;
                            resp["data"] = result;
                            
                            PostMessageToUI(resp);
                        }
                    } catch (const std::exception& e) {
                        nlohmann::json errResp;
                        errResp["id"] = reqId;
                        errResp["action"] = action;
                        errResp["success"] = false;
                        errResp["error"] = e.what();
                        PostMessageToUI(errResp);
                    }
                }
                return S_OK;
            }).Get(), &webMessageToken_);
}

nlohmann::json WebUIManager::DispatchApi(const std::string& action, const nlohmann::json& params) {
    if (action == "get_status") {
        return HandleGetStatus();
    } else if (action == "toggle_service") {
        bool start = params.value("start", true);
        return HandleToggleService(start);
    } else if (action == "get_ports") {
        return HandleGetPorts();
    } else if (action == "save_port") {
        return HandleSavePort(params);
    } else if (action == "delete_port") {
        return HandleDeletePort(params.value("id", 0));
    } else if (action == "move_port_up") {
        std::string grp = params.value("group", "");
        bool ok = Database::Instance().MoveProxyPortUp(params.value("id", 0), grp);
        if (ok) SharedStatusManager::Instance().NotifyPortsChanged();
        return { {"success", ok} };
    } else if (action == "move_port_down") {
        std::string grp = params.value("group", "");
        bool ok = Database::Instance().MoveProxyPortDown(params.value("id", 0), grp);
        if (ok) SharedStatusManager::Instance().NotifyPortsChanged();
        return { {"success", ok} };
    } else if (action == "get_port_groups") {
        auto groups = Database::Instance().GetAllPortGroups();
        return { {"success", true}, {"groups", groups} };
    } else if (action == "rename_port_group") {
        return HandleRenamePortGroup(params.value("oldName", ""), params.value("newName", ""));
    } else if (action == "toggle_port") {
        return HandleTogglePort(params.value("id", 0), params.value("enabled", true));
    } else if (action == "test_port") {
        return HandleTestPort(params.value("id", 0));
    } else if (action == "get_rules") {
        return HandleGetRules();
    } else if (action == "save_rule") {
        return HandleSaveRule(params);
    } else if (action == "delete_rule") {
        return HandleDeleteRule(params.value("id", 0));
    } else if (action == "toggle_rule") {
        return HandleToggleRule(params.value("id", 0), params.value("enabled", true));
    } else if (action == "move_rule_up") {
        bool ok = Database::Instance().MoveRoutingRuleUp(params.value("id", 0));
        if (ok) {
            RuleManager::Instance().ReloadRoutingRules();
            SharedStatusManager::Instance().NotifyRulesChanged();
        }
        return { {"success", ok} };
    } else if (action == "move_rule_down") {
        bool ok = Database::Instance().MoveRoutingRuleDown(params.value("id", 0));
        if (ok) {
            RuleManager::Instance().ReloadRoutingRules();
            SharedStatusManager::Instance().NotifyRulesChanged();
        }
        return { {"success", ok} };
    } else if (action == "get_china_direct_settings") {
        return HandleGetChinaDirectSettings();
    } else if (action == "save_china_direct_settings") {
        return HandleSaveChinaDirectSettings(params);
    } else if (action == "update_china_ip_subscription") {
        return HandleUpdateChinaIpSubscription(params);
    } else if (action == "get_users") {
        return HandleGetUsers();
    } else if (action == "save_user") {
        return HandleSaveUser(params);
    } else if (action == "delete_user") {
        return HandleDeleteUser(params.value("id", 0));
    } else if (action == "toggle_user") {
        return HandleToggleUser(params.value("id", 0), params.value("enabled", true));
    } else if (action == "move_user_up") {
        bool ok = Database::Instance().MoveUserUp(params.value("id", 0));
        return { {"success", ok} };
    } else if (action == "move_user_down") {
        bool ok = Database::Instance().MoveUserDown(params.value("id", 0));
        return { {"success", ok} };
    } else if (action == "reset_user_traffic") {
        return HandleResetUserTraffic(params.value("id", 0));
    } else if (action == "get_traffic_history") {
        std::string mode = params.value("mode", "");
        int count = 0;
        if (params.contains("count")) {
            count = params.value("count", 0);
        }
        if (mode.empty()) {
            if (params.contains("days")) {
                mode = "day";
                count = params.value("days", 90);
            } else {
                mode = "day";
                count = 90;
            }
        }
        if (count <= 0) {
            if (mode == "month") count = 12;
            else if (mode == "week") count = 52;
            else count = 90;
        }
        int userId = params.value("userId", -1);
        return HandleGetTrafficHistory(mode, count, userId);
    } else if (action == "get_node_traffic_analysis") {
        int portId = params.value("portId", -1);
        std::string mode = params.value("mode", "30days");
        int year = params.value("year", 0);
        return HandleGetNodeTrafficAnalysis(portId, mode, year);
    } else if (action == "get_connections") {
        return HandleGetConnections();
    } else if (action == "close_connection") {
        uint64_t connId = params.value("connId", (uint64_t)0);
        return HandleCloseConnection(connId);
    } else if (action == "get_logs") {
        int limit = params.value("limit", 200);
        return HandleGetLogs(limit);
    } else if (action == "clear_logs") {
        return HandleClearLogs();
    } else if (action == "get_blacklist" || action == "get_security_lists") {
        auto blackItems = Database::Instance().GetBlacklist();
        auto autoBanItems = Database::Instance().GetAutoBanList();
        nlohmann::json blackArr = nlohmann::json::array();
        nlohmann::json autoBanArr = nlohmann::json::array();
        int64_t nowSec = time(nullptr);

        for (const auto& b : blackItems) {
            blackArr.push_back({
                {"id", b.id},
                {"ip", b.ip},
                {"remark", b.remark},
                {"createdAt", b.createdAt}
            });
        }
        for (const auto& a : autoBanItems) {
            char timeBuf[64] = {};
            time_t expT = (time_t)a.expiryTime;
            struct tm tmVal;
            localtime_s(&tmVal, &expT);
            strftime(timeBuf, sizeof(timeBuf), "%Y-%m-%d %H:%M:%S", &tmVal);
            bool isExpired = (a.expiryTime <= nowSec);

            autoBanArr.push_back({
                {"id", a.id},
                {"ip", a.ip},
                {"reason", "连续认证失败自动封禁"},
                {"failCount", 5},
                {"bannedUntil", timeBuf},
                {"createdAt", a.createdAt},
                {"isExpired", isExpired}
            });
        }
        return {
            {"success", true},
            {"blacklist", blackArr},
            {"autobans", autoBanArr}
        };
    } else if (action == "add_blacklist") {
        std::string ip = params.value("ip", "");
        std::string remark = params.value("remark", params.value("reason", "管理员手动封禁"));
        if (ip.empty()) return { {"success", false}, {"error", "IP不能为空"} };
        bool ok = Database::Instance().AddToBlacklist(ip, remark);
        return { {"success", ok} };
    } else if (action == "delete_blacklist") {
        int id = params.value("id", 0);
        std::string ip = params.value("ip", "");
        bool ok = false;
        if (id > 0) ok = Database::Instance().RemoveFromBlacklist(id);
        else if (!ip.empty()) ok = Database::Instance().RemoveBlacklistByIP(ip);
        return { {"success", ok} };
    } else if (action == "remove_autoban" || action == "unban_ip") {
        int id = params.value("id", 0);
        std::string ip = params.value("ip", "");
        bool ok = false;
        if (id > 0) ok = Database::Instance().RemoveFromAutoBan(id);
        else if (!ip.empty()) ok = Database::Instance().RemoveAutoBanByIP(ip);
        return { {"success", ok} };
    } else if (action == "clear_autobans") {
        bool ok = Database::Instance().ClearAllAutoBans();
        return { {"success", ok} };
    } else if (action == "get_ban_policy") {
        bool enabled = (Database::Instance().GetConfig("ban_policy_enabled", "1") != "0");
        int windowMinutes = std::atoi(Database::Instance().GetConfig("login_fail_window", "5").c_str());
        int maxFailures = std::atoi(Database::Instance().GetConfig("login_fail_limit", "10").c_str());
        int banMinutes = std::atoi(Database::Instance().GetConfig("ban_duration", "60").c_str());
        if (windowMinutes <= 0) windowMinutes = 5;
        if (maxFailures <= 0) maxFailures = 10;
        if (banMinutes <= 0) banMinutes = 60;
        return {
            {"enabled", enabled},
            {"windowMinutes", windowMinutes},
            {"maxFailures", maxFailures},
            {"banMinutes", banMinutes}
        };
    } else if (action == "save_ban_policy") {
        bool enabled = params.value("enabled", true);
        int windowMinutes = params.value("windowMinutes", 5);
        int maxFailures = params.value("maxFailures", 10);
        int banMinutes = params.value("banMinutes", 60);
        Database::Instance().SetConfig("ban_policy_enabled", enabled ? "1" : "0");
        Database::Instance().SetConfig("login_fail_window", std::to_string(std::max(1, windowMinutes)));
        Database::Instance().SetConfig("login_fail_limit", std::to_string(std::max(1, maxFailures)));
        Database::Instance().SetConfig("ban_duration", std::to_string(std::max(1, banMinutes)));
        return { {"success", true} };
    } else if (action == "get_settings") {
        return HandleGetSettings();
    } else if (action == "save_settings") {
        return HandleSaveSettings(params);
    } else if (action == "get_service_status") {
        return HandleGetServiceStatus();
    } else if (action == "control_service") {
        return HandleControlService(params.value("command", ""));
    } else if (action == "get_subscriptions") {
        return HandleGetSubscriptions();
    } else if (action == "import_clash_sub") {
        std::string url = params.value("url", "");
        std::string name = params.value("name", "");
        std::string group = params.value("group", "");
        std::string includeFilter = params.value("includeFilter", "");
        std::string excludeFilter = params.value("excludeFilter", "");
        int resetCycleDays = params.value("resetCycleDays", 0);
        std::string resetStartDate = params.value("resetStartDate", "");
        return HandleImportClashSub(url, name, group, includeFilter, excludeFilter, resetCycleDays, resetStartDate);
    } else if (action == "update_subscription") {
        return HandleUpdateSubscription(params.value("id", 0));
    } else if (action == "refresh_clash_node") {
        return HandleRefreshPortNode(params.value("id", 0));
    } else if (action == "delete_subscription") {
        return HandleDeleteSubscription(params.value("id", 0));
    } else if (action == "save_subscription") {
        return HandleSaveSubscription(params);
    } else if (action == "open_url") {
        std::string targetUrl = params.value("url", "");
        if (!targetUrl.empty()) {
            std::wstring wUrl(targetUrl.begin(), targetUrl.end());
            ShellExecuteW(NULL, L"open", wUrl.c_str(), NULL, NULL, SW_SHOWNORMAL);
            return { {"success", true} };
        }
        return { {"success", false} };
    } else if (action == "window_control") {
        std::string cmd = params.value("command", "");
        if (cmd == "minimize") {
            ShowWindow(hWndParent_, SW_MINIMIZE);
        } else if (cmd == "maximize") {
            if (IsZoomed(hWndParent_)) {
                ShowWindow(hWndParent_, SW_RESTORE);
            } else {
                ShowWindow(hWndParent_, SW_MAXIMIZE);
            }
        } else if (cmd == "close") {
            PostMessage(hWndParent_, WM_CLOSE, 0, 0);
        }
        return { {"success", true} };
    } else if (action == "exit_app") {
        if (hWndParent_) {
            PostMessage(hWndParent_, WM_COMMAND, ID_TRAY_EXIT, 0);
        }
        return { {"success", true} };
    } else if (action == "generate_self_signed_cert") {
        std::string domains = params.value("domains", "");
        return HandleGenerateSelfSignedCert(domains);
    } else if (action == "load_custom_cert") {
        return HandleLoadCustomCert(params);
    } else if (action == "reset_default_cert") {
        return HandleResetDefaultCert();
    } else if (action == "export_cert") {
        return HandleExportCert();
    } else if (action == "export_config") {
        return HandleExportConfig();
    } else if (action == "import_config") {
        return HandleImportConfig(params);
    }
    return { {"error", "Unknown action: " + action} };
}

nlohmann::json WebUIManager::HandleGetStatus() {
    nlohmann::json res;
    bool isServiceRunning = ServiceManager::Instance().IsServiceRunning();
    bool running = isServiceRunning || ProxyServer::Instance().IsRunning();
    bool isServiceMode = isServiceRunning || MainWindow::Instance().IsConsoleOnlyMode();
    res["isRunning"] = running;
    res["isServiceMode"] = isServiceMode;

    bool sharedOk = false;
    bool sharedRunning = false;
    int sharedActiveConns = 0;
    int64_t sharedUpSpeed = 0, sharedDownSpeed = 0, sharedTotalUp = 0, sharedTotalDown = 0;
    int64_t sharedUptime = 0;

    if (SharedStatusManager::Instance().ReadStatus(sharedRunning, sharedActiveConns, sharedUpSpeed, sharedDownSpeed, sharedTotalUp, sharedTotalDown, &sharedUptime)) {
        sharedOk = true;
        res["isRunning"] = sharedRunning;
        res["activeConnections"] = sharedActiveConns;
        res["uploadSpeed"] = sharedUpSpeed;
        res["downloadSpeed"] = sharedDownSpeed;
        res["totalUpload"] = sharedTotalUp;
        res["totalDownload"] = sharedTotalDown;
        res["uptime"] = sharedUptime;
        res["uptime_seconds"] = sharedUptime;
        res["uptimeSeconds"] = sharedUptime;
    }

    if (!sharedOk) {
        res["activeConnections"] = isServiceRunning ? 0 : ProxyServer::Instance().GetActiveConnections();
        auto curData = TrafficMonitor::Instance().GetCurrentData();
        res["uploadSpeed"] = curData.uploadSpeed;
        res["downloadSpeed"] = curData.downloadSpeed;
        
        // 若总流量为 0，从数据库加载基准历史总流量
        int64_t totalUp = curData.totalUpload;
        int64_t totalDown = curData.totalDownload;
        if (totalUp == 0 && totalDown == 0) {
            Database::Instance().GetTotalTraffic(totalUp, totalDown);
        }
        res["totalUpload"] = totalUp;
        res["totalDownload"] = totalDown;

        int64_t uptime = running ? ProxyServer::Instance().GetUptime() : 0;
        res["uptime"] = uptime;
        res["uptime_seconds"] = uptime;
        res["uptimeSeconds"] = uptime;
    }
    
    // 近 7 天流量历史统计
    auto dailySummaries = Database::Instance().GetDailyTrafficHistory(7, -1);
    nlohmann::json history = nlohmann::json::array();
    for (const auto& d : dailySummaries) {
        history.push_back({
            {"date", d.date},
            {"upload", d.uploadBytes},
            {"download", d.downloadBytes}
        });
    }
    res["trafficHistory"] = history;
    res["version"] = Version::GetVersion();
    return res;
}

nlohmann::json WebUIManager::HandleToggleService(bool start) {
    bool isService = ServiceManager::Instance().IsServiceRunning() || MainWindow::Instance().IsConsoleOnlyMode();
    if (isService) {
        if (start) {
            ServiceManager::Instance().StartService();
        } else {
            ServiceManager::Instance().StopService();
        }
        bool serviceRunning = ServiceManager::Instance().IsServiceRunning();
        return { {"isRunning", serviceRunning}, {"isServiceMode", true} };
    }

    if (start) {
        ProxyServer::Instance().Start();
        TrafficMonitor::Instance().Start();
        Database::Instance().SetConfig("last_service_state", "1");
    } else {
        ProxyServer::Instance().Stop();
        TrafficMonitor::Instance().Stop();
        Database::Instance().SetConfig("last_service_state", "0");
    }
    return { {"isRunning", ProxyServer::Instance().IsRunning()}, {"isServiceMode", false} };
}

nlohmann::json WebUIManager::HandleGetPorts() {
    auto ports = Database::Instance().GetAllProxyPorts();
    nlohmann::json res = nlohmann::json::array();
    for (const auto& p : ports) {
        bool available = ProxyServer::Instance().IsProxyAvailable(p.id);
        
        std::string nodeType = "";
        std::string host = p.upstreamHost;
        int portVal = p.upstreamPort;

        if (p.upstreamType == "clash") {
            // 从 clashConfig 解析出真实的节点协议 (vmess, ss, trojan, vless 等)
            static const std::regex typeRegex(R"((?:^|[,\s{])type\s*:\s*["']?([a-zA-Z0-9_-]+))", std::regex::icase);
            std::smatch m;
            if (std::regex_search(p.clashConfig, m, typeRegex)) {
                nodeType = m[1].str();
            }
            if (host.empty() || portVal <= 0) {
                static const std::regex serverRegex(R"((?:^|[,\s{])server\s*:\s*["']?([^,\s"'\r\n}]+))", std::regex::icase);
                static const std::regex portRegex(R"((?:^|[,\s{])port\s*:\s*(\d+))", std::regex::icase);
                if (host.empty() && std::regex_search(p.clashConfig, m, serverRegex)) {
                    host = m[1].str();
                }
                if (portVal <= 0 && std::regex_search(p.clashConfig, m, portRegex)) {
                    try { portVal = std::stoi(m[1].str()); } catch (...) {}
                }
            }
        }

        res.push_back({
            {"id", p.id},
            {"listenPort", p.listenPort},
            {"upstreamType", p.upstreamType},
            {"nodeType", nodeType},
            {"upstreamHost", host},
            {"upstreamPort", portVal},
            {"upstreamUser", p.upstreamUser},
            {"description", p.description},
            {"priority", p.priority},
            {"enabled", p.enabled},
            {"autoCheck", p.autoCheck},
            {"allowedTargets", p.allowedTargets},
            {"isAvailable", available},
            {"latency", ProxyServer::Instance().GetProxyLatency(p.id)},
            {"subscriptionId", p.clashSubscriptionId},
            {"clashNodeName", p.clashNodeName},
            {"groupName", p.groupName},
            {"clashConfig", p.clashConfig},
            {"xrayConfig", p.xrayConfig}
        });
    }
    return res;
}

nlohmann::json WebUIManager::HandleSavePort(const nlohmann::json& p) {
    ProxyPort port;
    port.id = p.value("id", 0);
    port.listenPort = p.value("listenPort", 0);
    port.upstreamType = p.value("upstreamType", "http");
    port.upstreamHost = p.value("upstreamHost", "");
    port.upstreamPort = p.value("upstreamPort", 0);
    port.upstreamUser = p.value("upstreamUser", "");
    port.upstreamPass = p.value("upstreamPass", "");
    port.description = p.value("description", "");
    port.groupName = p.value("groupName", "");
    port.enabled = p.value("enabled", true);
    port.autoCheck = p.value("autoCheck", true);
    port.allowedTargets = p.value("allowedTargets", "*");
    port.xrayConfig = p.value("xrayConfig", "");
    port.clashConfig = p.value("clashConfig", "");

    bool ok = false;
    if (port.id > 0) {
        ProxyPort existing;
        if (Database::Instance().GetProxyPort(port.id, existing)) {
            if (port.upstreamUser.empty()) port.upstreamUser = existing.upstreamUser;
            if (port.upstreamPass.empty()) port.upstreamPass = existing.upstreamPass;
            if (port.xrayConfig.empty()) port.xrayConfig = existing.xrayConfig;
            if (!p.contains("clashConfig") || port.clashConfig.empty()) {
                port.clashConfig = existing.clashConfig;
            }
            if (!p.contains("groupName")) port.groupName = existing.groupName;
            port.clashSubscriptionId = existing.clashSubscriptionId;
            port.clashNodeName = existing.clashNodeName;
            port.priority = existing.priority;
            if (!p.contains("enabled")) port.enabled = existing.enabled;
            if (!p.contains("autoCheck")) port.autoCheck = existing.autoCheck;
            if (!p.contains("allowedTargets") || port.allowedTargets == "*") port.allowedTargets = existing.allowedTargets;
        }

        // 同步提取并补全 clash 节点的 host 和 port（若为空）
        if (port.upstreamType == "clash" && !port.clashConfig.empty()) {
            std::smatch m;
            if (port.upstreamHost.empty()) {
                static const std::regex serverRegex(R"((?:^|[,\s{])server\s*:\s*["']?([^,\s"'\r\n}]+))", std::regex::icase);
                if (std::regex_search(port.clashConfig, m, serverRegex)) port.upstreamHost = m[1].str();
            }
            if (port.upstreamPort == 0) {
                static const std::regex portRegex(R"((?:^|[,\s{])port\s*:\s*(\d+))", std::regex::icase);
                if (std::regex_search(port.clashConfig, m, portRegex)) {
                    try { port.upstreamPort = std::stoi(m[1].str()); } catch (...) {}
                }
            }
        }

        ok = Database::Instance().UpdateProxyPort(port);
        // 如果 clash 正在运行，热重启以便新配置立即生效
        if (port.upstreamType == "clash" && ClashManager::Instance().IsRunning(port.id)) {
            ClashManager::Instance().StopClash(port.id);
            if (port.enabled) {
                ClashManager::Instance().StartClash(port.id, port.clashConfig);
            }
        }
        if (port.upstreamType == "clash" && !port.clashConfig.empty()) {
            std::smatch m;
            if (port.upstreamHost.empty()) {
                static const std::regex serverRegex(R"((?:^|[,\s{])server\s*:\s*["']?([^,\s"'\r\n}]+))", std::regex::icase);
                if (std::regex_search(port.clashConfig, m, serverRegex)) port.upstreamHost = m[1].str();
            }
            if (port.upstreamPort == 0) {
                static const std::regex portRegex(R"((?:^|[,\s{])port\s*:\s*(\d+))", std::regex::icase);
                if (std::regex_search(port.clashConfig, m, portRegex)) {
                    try { port.upstreamPort = std::stoi(m[1].str()); } catch (...) {}
                }
            }
        }
        
        // 节点消重检测：检查是否已有相同配置的节点
        auto allPorts = Database::Instance().GetAllProxyPorts();
        bool foundDuplicate = false;
        for (auto& existing : allPorts) {
            bool isDup = false;
            if (port.listenPort > 0 && existing.listenPort == port.listenPort) {
                isDup = true;
            } else if (port.listenPort == 0 && existing.listenPort == 0 &&
                       existing.upstreamType == port.upstreamType &&
                       existing.upstreamHost == port.upstreamHost &&
                       existing.upstreamPort == port.upstreamPort &&
                       (existing.groupName == port.groupName || port.groupName.empty())) {
                isDup = true;
            }
            if (isDup) {
                existing.description = port.description;
                if (!port.clashConfig.empty()) existing.clashConfig = port.clashConfig;
                if (!port.groupName.empty()) existing.groupName = port.groupName;
                existing.enabled = port.enabled;
                ok = Database::Instance().UpdateProxyPort(existing);
                port.id = existing.id;
                foundDuplicate = true;
                break;
            }
        }
        if (!foundDuplicate) {
            ok = Database::Instance().AddProxyPort(port);
        }
    }
    Database::Instance().DeduplicateProxyPorts();
    if (ok && port.listenPort > 0 && ProxyServer::Instance().IsRunning()) {
        ProxyServer::Instance().ReloadPorts();
    }
    SharedStatusManager::Instance().NotifyPortsChanged();
    return { {"success", ok} };
}

nlohmann::json WebUIManager::HandleDeletePort(int id) {
    ProxyPort port;
    if (Database::Instance().GetProxyPort(id, port)) {
        if (port.upstreamType == "clash") ClashManager::Instance().StopClash(id);
        else if (port.upstreamType == "xray") XrayManager::Instance().StopXray(id);
        bool ok = Database::Instance().DeleteProxyPort(id);
        if (ok && port.listenPort > 0 && ProxyServer::Instance().IsRunning()) {
            ProxyServer::Instance().ReloadPorts();
        }
        SharedStatusManager::Instance().NotifyPortsChanged();
        return { {"success", ok} };
    }
    bool ok = Database::Instance().DeleteProxyPort(id);
    SharedStatusManager::Instance().NotifyPortsChanged();
    return { {"success", ok} };
}

nlohmann::json WebUIManager::HandleTogglePort(int id, bool enabled) {
    ProxyPort port;
    if (Database::Instance().GetProxyPort(id, port)) {
        port.enabled = enabled;
        Database::Instance().UpdateProxyPort(port);
        if (!enabled) {
            if (port.upstreamType == "clash") ClashManager::Instance().StopClash(id);
            else if (port.upstreamType == "xray") XrayManager::Instance().StopXray(id);
        }
        if (port.listenPort > 0 && ProxyServer::Instance().IsRunning()) {
            ProxyServer::Instance().ReloadPorts();
        }
        SharedStatusManager::Instance().NotifyPortsChanged();
        return { {"success", true} };
    }
    return { {"success", false} };
}

nlohmann::json WebUIManager::HandleTestPort(int id) {
    ProxyPort port;
    if (!Database::Instance().GetProxyPort(id, port)) {
        return { {"success", false}, {"error", "Port not found"} };
    }
    std::string targetsStr = Database::Instance().GetConfig("health_check_targets", "www.bing.com:443, www.google.com:443");
    std::vector<std::string> targets;
    std::string cur;
    for (char c : targetsStr) {
        if (c == ',' || c == ';' || c == '\n' || c == '\r') {
            while (!cur.empty() && isspace((unsigned char)cur.front())) cur.erase(cur.begin());
            while (!cur.empty() && isspace((unsigned char)cur.back())) cur.pop_back();
            if (!cur.empty()) {
                targets.push_back(cur);
                cur.clear();
            }
        } else {
            cur += c;
        }
    }
    while (!cur.empty() && isspace((unsigned char)cur.front())) cur.erase(cur.begin());
    while (!cur.empty() && isspace((unsigned char)cur.back())) cur.pop_back();
    if (!cur.empty()) targets.push_back(cur);
    if (targets.empty()) targets = {"www.bing.com:443", "www.google.com:443"};

    int ms = -1;
    bool ok = ProxyServer::Instance().CheckProxyConnectivity(port, targets, &ms);
    ProxyServer::Instance().UpdateProxyStatus(port.id, ok, ms);
    return { {"success", ok}, {"latency", ms} };
}

nlohmann::json WebUIManager::HandleRenamePortGroup(const std::string& oldName, const std::string& newName) {
    if (oldName.empty() || newName.empty() || oldName == newName) {
        return { {"success", false}, {"error", "分组名称不能为空或与原名称相同"} };
    }
    bool ok = Database::Instance().RenamePortGroup(oldName, newName);
    if (ok) {
        RuleManager::Instance().ReloadRoutingRules();
        SharedStatusManager::Instance().NotifyRulesChanged();
    }
    return { {"success", ok} };
}

nlohmann::json WebUIManager::HandleGetRules() {
    auto rules = Database::Instance().GetAllRoutingRules();
    nlohmann::json res = nlohmann::json::array();
    for (const auto& r : rules) {
        res.push_back({
            {"id", r.id},
            {"priority", r.priority},
            {"matchType", r.matchType},
            {"matchValue", r.matchValue},
            {"proxyId", r.proxyId},
            {"targetGroup", r.targetGroup},
            {"enabled", r.enabled},
            {"description", r.description},
            {"isFallback", r.isFallback}
        });
    }
    return res;
}

nlohmann::json WebUIManager::HandleSaveRule(const nlohmann::json& r) {
    RoutingRule rule;
    rule.id = r.value("id", 0);
    rule.priority = r.value("priority", 0);
    rule.matchType = r.value("matchType", "domain");
    rule.matchValue = r.value("matchValue", "");
    rule.proxyId = r.value("proxyId", 0);
    rule.targetGroup = r.value("targetGroup", "");
    rule.enabled = r.value("enabled", true);
    rule.description = r.value("description", "");
    rule.isFallback = r.value("isFallback", false);

    bool ok = false;
    if (rule.id > 0) {
        RoutingRule existing;
        if (Database::Instance().GetRoutingRule(rule.id, existing)) {
            if (existing.isFallback) {
                rule.isFallback = true;
                rule.matchType = "all";
                rule.matchValue = "*";
                if (rule.description.empty()) rule.description = "默认兜底规则";
            }
            if (rule.priority == 0) rule.priority = existing.priority;
            if (!r.contains("enabled")) rule.enabled = existing.enabled;
            if (!r.contains("targetGroup")) rule.targetGroup = existing.targetGroup;
        }
        ok = Database::Instance().UpdateRoutingRule(rule);
    } else {
        rule.isFallback = false;
        ok = Database::Instance().AddRoutingRule(rule);
    }
    RuleManager::Instance().ReloadRoutingRules();
    SharedStatusManager::Instance().NotifyRulesChanged();
    return { {"success", ok} };
}

nlohmann::json WebUIManager::HandleDeleteRule(int id) {
    RoutingRule existing;
    if (Database::Instance().GetRoutingRule(id, existing) && existing.isFallback) {
        return { {"success", false}, {"error", "默认兜底规则不可删除"} };
    }
    bool ok = Database::Instance().DeleteRoutingRule(id);
    RuleManager::Instance().ReloadRoutingRules();
    SharedStatusManager::Instance().NotifyRulesChanged();
    return { {"success", ok} };
}

nlohmann::json WebUIManager::HandleToggleRule(int id, bool enabled) {
    RoutingRule rule;
    if (Database::Instance().GetRoutingRule(id, rule)) {
        rule.enabled = enabled;
        bool ok = Database::Instance().UpdateRoutingRule(rule);
        if (ok) {
            RuleManager::Instance().ReloadRoutingRules();
            SharedStatusManager::Instance().NotifyRulesChanged();
        }
        return { {"success", ok} };
    }
    return { {"success", false} };
}

nlohmann::json WebUIManager::HandleGetUsers() {
    auto users = Database::Instance().GetAllUsers();
    nlohmann::json res = nlohmann::json::array();
    for (const auto& u : users) {
        int64_t monthlyUsed = Database::Instance().GetUserMonthlyUsage(u.id);
        int64_t totalUsed = Database::Instance().GetUserTotalUsage(u.id);
        res.push_back({
            {"id", u.id},
            {"username", u.username},
            {"hasPassword", !u.password.empty()},
            {"enabled", u.enabled},
            {"dailyLimit", u.dailyLimit},
            {"monthlyLimit", u.monthlyLimit},
            {"monthlyTrafficLimit", u.monthlyLimit},
            {"monthlyUsed", monthlyUsed},
            {"totalUsed", totalUsed},
            {"allowedIPs", u.allowedIPs},
            {"allowedTargets", u.allowedTargets},
            {"priority", u.priority}
        });
    }
    return res;
}

nlohmann::json WebUIManager::HandleSaveUser(const nlohmann::json& u) {
    UserInfo user;
    user.id = u.value("id", 0);
    user.username = u.value("username", "");
    user.password = u.value("password", "");
    user.enabled = u.value("enabled", true);
    int64_t mLimit = u.value("monthlyLimit", u.value("monthlyTrafficLimit", (int64_t)0));
    user.monthlyLimit = mLimit;
    user.dailyLimit = u.value("dailyLimit", (int64_t)0);
    user.allowedIPs = u.value("allowedIPs", "");
    user.allowedTargets = u.value("allowedTargets", "*");

    if (user.username.empty()) {
        return { {"success", false}, {"error", "用户名不能为空"} };
    }

    bool clearPassword = u.value("clearPassword", false);
    if (user.id > 0) {
        UserInfo existing;
        if (Database::Instance().GetUser(user.id, existing)) {
            if (clearPassword) {
                user.password = "";
            } else if (user.password.empty()) {
                user.password = existing.password;
            }
            if (user.allowedTargets.empty() || user.allowedTargets == "*") {
                user.allowedTargets = existing.allowedTargets;
            }
            user.remark = existing.remark;
            user.expiryDate = existing.expiryDate;
            user.priority = existing.priority;
        }
    }

    // 用户密码是可选项，如不输入密码则需要输入客户端IP规则
    if (user.password.empty()) {
        if (user.allowedIPs.empty() || user.allowedIPs == "*") {
            return { {"success", false}, {"error", "用户密码为可选项；如不输入密码，则必须输入具体的客户端IP规则（不支持留空或*）"} };
        }
    }

    bool ok = false;
    if (user.id > 0) {
        ok = Database::Instance().UpdateUser(user);
    } else {
        ok = Database::Instance().AddUser(user);
    }
    return { {"success", ok} };
}

nlohmann::json WebUIManager::HandleDeleteUser(int id) {
    bool ok = Database::Instance().DeleteUser(id);
    return { {"success", ok} };
}

nlohmann::json WebUIManager::HandleToggleUser(int id, bool enabled) {
    UserInfo user;
    if (Database::Instance().GetUser(id, user)) {
        user.enabled = enabled;
        bool ok = Database::Instance().UpdateUser(user);
        return { {"success", ok} };
    }
    return { {"success", false} };
}

nlohmann::json WebUIManager::HandleResetUserTraffic(int id) {
    bool ok = Database::Instance().ResetUserTraffic(id);
    return { {"success", ok} };
}

nlohmann::json WebUIManager::HandleGetTrafficHistory(const std::string& mode, int count, int userId) {
    auto list = Database::Instance().GetTrafficTrend(mode, count, userId);
    nlohmann::json history = nlohmann::json::array();
    int64_t totalUp = 0;
    int64_t totalDown = 0;

    for (const auto& item : list) {
        totalUp += item.uploadBytes;
        totalDown += item.downloadBytes;
        history.push_back({
            {"date", item.date},
            {"label", item.label},
            {"tooltip", item.tooltip},
            {"upload", item.uploadBytes},
            {"download", item.downloadBytes},
            {"total", item.totalBytes}
        });
    }

    int64_t totalBytes = totalUp + totalDown;
    int64_t avg = count > 0 ? totalBytes / count : 0;

    nlohmann::json res;
    res["mode"] = mode;
    res["count"] = count;
    res["days"] = count;
    res["userId"] = userId;
    res["totalUpload"] = totalUp;
    res["totalDownload"] = totalDown;
    res["totalBytes"] = totalBytes;
    res["average"] = avg;
    res["dailyAverage"] = avg;
    res["history"] = history;
    return res;
}

nlohmann::json WebUIManager::HandleGetNodeTrafficAnalysis(int portId, const std::string& mode, int year) {
    nlohmann::json res;
    res["portId"] = portId;
    res["mode"] = mode;
    
    // 获取节点名称说明
    std::string portName = "全网所有节点汇总";
    if (portId > 0) {
        ProxyPort port;
        if (Database::Instance().GetProxyPort(portId, port)) {
            if (!port.description.empty()) {
                portName = port.description;
            } else if (!port.upstreamHost.empty()) {
                portName = port.upstreamHost + ":" + std::to_string(port.upstreamPort);
            } else {
                portName = "节点 #" + std::to_string(portId);
            }
        } else {
            portName = "节点 #" + std::to_string(portId);
        }
    }
    res["portName"] = portName;
    res["availableYears"] = Database::Instance().GetPortTrafficYears();

    if (mode == "annual") {
        if (year <= 0) {
            try {
                year = std::stoi(Utils::GetCurrentDate().substr(0, 4));
            } catch (...) {
                year = 2026;
            }
        }
        res["year"] = year;
        auto list = Database::Instance().GetPortAnnualTrafficHistory(year, portId);
        nlohmann::json history = nlohmann::json::array();
        int64_t totalUp = 0;
        int64_t totalDown = 0;
        int64_t peakTotal = 0;
        std::string peakMonth = "-";

        for (const auto& item : list) {
            totalUp += item.uploadBytes;
            totalDown += item.downloadBytes;
            int64_t t = item.uploadBytes + item.downloadBytes;
            if (t > peakTotal) {
                peakTotal = t;
                peakMonth = item.month;
            }
            history.push_back({
                {"label", item.month},
                {"upload", item.uploadBytes},
                {"download", item.downloadBytes},
                {"total", t}
            });
        }

        res["totalUpload"] = totalUp;
        res["totalDownload"] = totalDown;
        res["totalBytes"] = totalUp + totalDown;
        res["averageBytes"] = (totalUp + totalDown) / 12; // 12个月月均
        res["peakLabel"] = peakMonth;
        res["peakBytes"] = peakTotal;
        res["history"] = history;
    } else {
        // 默认为 30 天日用量模式
        int days = 30;
        res["days"] = days;
        auto list = Database::Instance().GetPortDailyTrafficHistory(days, portId);
        nlohmann::json history = nlohmann::json::array();
        int64_t totalUp = 0;
        int64_t totalDown = 0;
        int64_t peakTotal = 0;
        std::string peakDay = "-";

        for (const auto& item : list) {
            totalUp += item.uploadBytes;
            totalDown += item.downloadBytes;
            int64_t t = item.uploadBytes + item.downloadBytes;
            if (t > peakTotal) {
                peakTotal = t;
                peakDay = item.date;
            }
            history.push_back({
                {"label", item.date},
                {"upload", item.uploadBytes},
                {"download", item.downloadBytes},
                {"total", t}
            });
        }

        res["totalUpload"] = totalUp;
        res["totalDownload"] = totalDown;
        res["totalBytes"] = totalUp + totalDown;
        res["averageBytes"] = days > 0 ? (totalUp + totalDown) / days : 0;
        res["peakLabel"] = peakDay;
        res["peakBytes"] = peakTotal;
        res["history"] = history;
    }
    return res;
}

nlohmann::json WebUIManager::HandleGetConnections() {
    std::vector<RealtimeConnection> conns = RealtimeConnectionManager::Instance().GetConnectionsSnapshot();

    // 如果本地没有活跃连接，且后台服务正在运行，从跨进程共享内存读取实时连接快照
    if (conns.empty() && SharedStatusManager::Instance().HasActiveHeartbeat()) {
        std::vector<RealtimeConnection> sharedConns;
        if (SharedStatusManager::Instance().ReadConnections(sharedConns)) {
            conns = std::move(sharedConns);
        }
    }

    nlohmann::json res = nlohmann::json::array();
    for (const auto& c : conns) {
        res.push_back({
            {"id", c.id},
            {"username", c.username},
            {"clientIP", c.clientIP},
            {"protocol", c.protocol.empty() ? "TCP" : c.protocol},
            {"inboundType", c.inboundType.empty() ? "HTTP" : c.inboundType},
            {"targetHost", c.targetHost},
            {"targetPort", c.targetPort},
            {"proxyDesc", c.proxyDesc},
            {"uploadBytes", c.uploadBytes},
            {"downloadBytes", c.downloadBytes},
            {"startTime", c.timestamp},
            {"timestamp", c.timestamp},
            {"isClosed", !c.active}
        });
    }
    return res;
}

nlohmann::json WebUIManager::HandleCloseConnection(uint64_t connId) {
    RealtimeConnectionManager::Instance().CloseConnection(connId);
    if (SharedStatusManager::Instance().HasActiveHeartbeat()) {
        SharedStatusManager::Instance().RequestCloseConnection(connId);
    }
    return { {"success", true} };
}

nlohmann::json WebUIManager::HandleGetLogs(int limit) {
    auto logs = ConnectionLogger::Instance().GetRecentLogs(limit);
    nlohmann::json res = nlohmann::json::array();
    for (auto it = logs.rbegin(); it != logs.rend(); ++it) {
        res.push_back({
            {"timestamp", it->timestamp},
            {"username", it->username},
            {"clientIP", it->clientIP},
            {"protocol", it->protocol.empty() ? "TCP" : it->protocol},
            {"inboundType", it->inboundType.empty() ? "HTTP" : it->inboundType},
            {"targetHost", it->targetHost},
            {"targetPort", it->targetPort},
            {"action", it->action},
            {"proxyDesc", it->proxyDesc}
        });
    }
    return res;
}

nlohmann::json WebUIManager::HandleClearLogs() {
    ConnectionLogger::Instance().Clear();
    return { {"success", true} };
}

nlohmann::json WebUIManager::HandleGetSettings() {
    nlohmann::json res;
    res["inbound_proxy_type"] = Database::Instance().GetConfig("inbound_proxy_type", "all");
    res["auto_proxy_port"] = Database::Instance().GetConfig("auto_proxy_port", "1080");
    res["relay_buffer_size_kb"] = Database::Instance().GetConfig("relay_buffer_size_kb", "64");
    res["log_retention_days"] = Database::Instance().GetConfig("log_retention_days", "30");
    res["traffic_retention_days"] = Database::Instance().GetConfig("traffic_retention_days", "365");
    res["port_traffic_retention_days"] = Database::Instance().GetConfig("port_traffic_retention_days", "60");

    // 数据占用量统计
    int64_t logBytes = 0;
    int logFiles = 0;
    ConnectionLogger::Instance().GetStorageInfo(logBytes, logFiles);
    res["log_storage_bytes"] = logBytes;
    res["log_storage_count"] = logFiles;
    res["log_storage_desc"] = (logFiles > 0) ? ("当前占用: " + Utils::FormatBytes(logBytes) + " (" + std::to_string(logFiles) + "个日志文件)") : "当前占用: 0 B";

    int64_t trafficRecords = 0, trafficBytes = 0;
    int trafficDays = 0;
    Database::Instance().GetTrafficStorageInfo(trafficRecords, trafficBytes, trafficDays);
    res["traffic_storage_bytes"] = trafficBytes;
    res["traffic_storage_count"] = trafficRecords;
    res["traffic_storage_days"] = trafficDays;
    res["traffic_storage_desc"] = (trafficRecords > 0) ? ("当前占用: " + Utils::FormatBytes(trafficBytes) + " (" + std::to_string(trafficRecords) + "条记录" + (trafficDays > 0 ? (", 跨度" + std::to_string(trafficDays) + "天)") : ")")) : "当前占用: 0 B";

    int64_t portRecords = 0, portBytes = 0;
    int portDays = 0;
    Database::Instance().GetPortTrafficStorageInfo(portRecords, portBytes, portDays);
    res["port_traffic_storage_bytes"] = portBytes;
    res["port_traffic_storage_count"] = portRecords;
    res["port_traffic_storage_days"] = portDays;
    res["port_traffic_storage_desc"] = (portRecords > 0) ? ("当前占用: " + Utils::FormatBytes(portBytes) + " (" + std::to_string(portRecords) + "条记录" + (portDays > 0 ? (", 跨度" + std::to_string(portDays) + "天)") : ")")) : "当前占用: 0 B";

    res["min_to_tray"] = Database::Instance().GetConfig("min_to_tray", "0") == "1";
    res["close_to_tray"] = Database::Instance().GetConfig("close_to_tray", "1") == "1";
    res["health_check_targets"] = Database::Instance().GetConfig("health_check_targets", "www.bing.com:443, www.google.com:443");
    
    // TLS 证书配置
    res["cert_status"] = SchannelSession::GetCertStatusInfo();
    std::string certMode = Database::Instance().GetConfig("https_cert_mode", "default");
    std::string certFile = Database::Instance().GetConfig("https_cert_file", "");
    std::string keyFile = Database::Instance().GetConfig("https_key_file", "");
    if (certFile.empty() && certMode == "custom") {
        certFile = Database::Instance().GetConfig("https_cert_mirror_file", "");
        keyFile = Database::Instance().GetConfig("https_key_mirror_file", "");
    }
    res["cert_mode"] = certMode;
    res["cert_file"] = certFile;
    res["key_file"] = keyFile;
    res["cert_domains"] = Database::Instance().GetConfig("self_signed_cert_domains", "localhost,127.0.0.1,::1,ProxyRelay");
    res["cert_expiry"] = SchannelSession::GetCurrentCertExpiry();
    
    // 开机自启状态检查
    HKEY hKey;
    bool autoStart = false;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExW(hKey, L"ProxyRelay", nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
            autoStart = true;
        }
        RegCloseKey(hKey);
    }
    res["auto_start"] = autoStart;
    return res;
}

nlohmann::json WebUIManager::HandleSaveSettings(const nlohmann::json& s) {
    if (s.contains("inbound_proxy_type")) {
        Database::Instance().SetConfig("inbound_proxy_type", s["inbound_proxy_type"].get<std::string>());
    }
    if (s.contains("self_signed_cert_domains")) {
        Database::Instance().SetConfig("self_signed_cert_domains", s["self_signed_cert_domains"].get<std::string>());
    }
    if (s.contains("auto_proxy_port")) {
        Database::Instance().SetConfig("auto_proxy_port", s["auto_proxy_port"].get<std::string>());
    }
    if (s.contains("relay_buffer_size_kb")) {
        Database::Instance().SetConfig("relay_buffer_size_kb", s["relay_buffer_size_kb"].get<std::string>());
    }
    if (s.contains("log_retention_days")) {
        Database::Instance().SetConfig("log_retention_days", s["log_retention_days"].get<std::string>());
    }
    if (s.contains("traffic_retention_days")) {
        Database::Instance().SetConfig("traffic_retention_days", s["traffic_retention_days"].get<std::string>());
        Database::Instance().CleanOldTrafficRecords();
    }
    if (s.contains("port_traffic_retention_days")) {
        Database::Instance().SetConfig("port_traffic_retention_days", s["port_traffic_retention_days"].get<std::string>());
        Database::Instance().CleanOldTrafficRecords();
    }
    if (s.contains("min_to_tray")) {
        Database::Instance().SetConfig("min_to_tray", s["min_to_tray"].get<bool>() ? "1" : "0");
    }
    if (s.contains("close_to_tray")) {
        Database::Instance().SetConfig("close_to_tray", s["close_to_tray"].get<bool>() ? "1" : "0");
    }
    if (s.contains("health_check_targets")) {
        Database::Instance().SetConfig("health_check_targets", s["health_check_targets"].get<std::string>());
        ProxyServer::Instance().TriggerCheck();
    }
    if (s.contains("auto_start")) {
        bool enable = s["auto_start"].get<bool>();
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
    return { {"success", true} };
}

nlohmann::json WebUIManager::HandleGetServiceStatus() {
    bool installed = ServiceManager::Instance().IsServiceInstalled();
    bool running = ServiceManager::Instance().IsServiceRunning();
    return { {"installed", installed}, {"running", running} };
}

nlohmann::json WebUIManager::HandleControlService(const std::string& action) {
    bool ok = false;
    if (action == "install") {
        ok = ServiceManager::Instance().InstallService();
    } else if (action == "uninstall") {
        ok = ServiceManager::Instance().UninstallService();
    } else if (action == "start") {
        if (ProxyServer::Instance().IsRunning()) {
            ProxyServer::Instance().Stop();
            TrafficMonitor::Instance().Stop();
        }
        MainWindow::Instance().SetConsoleOnlyMode(true);
        ok = ServiceManager::Instance().StartService();
    } else if (action == "stop") {
        ok = ServiceManager::Instance().StopService();
    }
    return { {"success", ok} };
}

nlohmann::json WebUIManager::HandleGetSubscriptions() {
    auto subs = Database::Instance().GetAllSubscriptions();
    nlohmann::json res = nlohmann::json::array();
    for (auto& s : subs) {
        // 自动计算流量重置周期进度
        if (s.resetCycleDays == 30 || s.resetCycleDays < 0) s.resetCycleDays = 0; // 0 表示按当月自然月天数
        if (s.resetStartDate.empty()) {
            s.resetStartDate = s.createdAt.empty() ? Utils::GetCurrentDate().substr(0, 10) : s.createdAt.substr(0, 10);
            Database::Instance().UpdateSubscription(s);
        }
        
        auto cycleInfo = ClashManager::CalculateCycleInfo(s.resetStartDate, s.resetCycleDays, s.lastResetCycle, s.createdAt);

        auto ports = Database::Instance().GetPortsBySubscriptionId(s.id);
        res.push_back({
            {"id", s.id},
            {"name", s.name},
            {"url", s.url},
            {"updateIntervalDays", s.updateIntervalDays},
            {"updateTime", s.updateTime},
            {"lastUpdated", s.lastUpdated},
            {"createdAt", s.createdAt},
            {"uploadBytes", s.uploadBytes},
            {"downloadBytes", s.downloadBytes},
            {"totalBytes", s.totalBytes},
            {"expireTime", s.expireTime},
            {"websiteUrl", s.websiteUrl},
            {"includeFilter", s.includeFilter},
            {"excludeFilter", s.excludeFilter},
            {"resetCycleDays", s.resetCycleDays},
            {"resetStartDate", s.resetStartDate},
            {"curCycle", cycleInfo.curCycle},
            {"daysPassed", cycleInfo.daysPassed},
            {"daysRemaining", cycleInfo.daysRemaining},
            {"cycleTotalDays", cycleInfo.cycleTotalDays},
            {"cyclePercent", cycleInfo.cyclePercent},
            {"curCycleStart", cycleInfo.curCycleStart},
            {"nextResetDate", cycleInfo.nextResetDate},
            {"isNaturalMonth", cycleInfo.isNaturalMonth},
            {"nodeCount", (int)ports.size()}
        });
    }
    return res;
}

nlohmann::json WebUIManager::HandleImportClashSub(const std::string& url, const std::string& name, const std::string& group, const std::string& includeFilter, const std::string& excludeFilter, int resetCycleDays, const std::string& resetStartDate) {
    if (url.empty()) return { {"success", false}, {"error", "URL 或 YAML 节点文本不能为空"} };
    
    std::string yamlContent;
    ClashManager::SubscriptionUserInfo userInfo;
    bool isHttp = (url.rfind("http://", 0) == 0 || url.rfind("https://", 0) == 0);
    if (isHttp) {
        yamlContent = ClashManager::DownloadSubscription(url, &userInfo);
        if (yamlContent.empty()) {
            return { {"success", false}, {"error", "无法从订阅 URL 下载内容，请检查网络或链接是否有效"} };
        }
    } else {
        yamlContent = url;
        ClashManager::ParseSubscriptionContentUserInfo(yamlContent, userInfo);
    }
    
    auto rawNodes = ClashManager::ParseSubscriptionNodes(yamlContent);
    if (rawNodes.empty()) {
        return { {"success", false}, {"error", "未从输入内容中解析到可用代理节点，请检查链接或 YAML 节点格式"} };
    }

    // 筛选与消重处理
    auto nodes = ClashManager::FilterAndDeduplicateNodes(rawNodes, includeFilter, excludeFilter);
    if (nodes.empty()) {
        return { {"success", false}, {"error", "未能筛选到匹配的代理节点（已解析 " + std::to_string(rawNodes.size()) + " 个原始节点，但均未通过筛选规则或被排除规则过滤）"} };
    }
    
    ClashSubscription sub;
    sub.name = name.empty() ? (isHttp ? "Clash订阅" : "自定义节点导入") : name;
    sub.url = isHttp ? url : "local:custom";
    sub.rawContent = yamlContent;
    sub.updateIntervalDays = 1;
    sub.updateTime = "04:00";
    sub.lastUpdated = Utils::GetCurrentDate();
    sub.includeFilter = includeFilter;
    sub.excludeFilter = excludeFilter;
    sub.uploadBytes = userInfo.uploadBytes;
    sub.downloadBytes = userInfo.downloadBytes;
    sub.totalBytes = userInfo.totalBytes;
    sub.expireTime = userInfo.expireTime;
    sub.websiteUrl = userInfo.websiteUrl;
    sub.resetCycleDays = (resetCycleDays <= 0 || resetCycleDays == 30) ? 0 : resetCycleDays;
    if (!resetStartDate.empty()) {
        sub.resetStartDate = resetStartDate;
    } else if (!userInfo.startDate.empty()) {
        sub.resetStartDate = userInfo.startDate;
    } else {
        sub.resetStartDate = Utils::GetCurrentDate().substr(0, 10);
    }
    sub.cycleOffsetBytes = 0;
    sub.lastResetCycle = 0;
    
    int subId = 0;
    if (Database::Instance().AddSubscription(sub)) {
        auto allSubs = Database::Instance().GetAllSubscriptions();
        subId = allSubs.empty() ? 1 : allSubs.back().id;
    }
    
    int imported = 0;
    for (const auto& node : nodes) {
        ProxyPort p;
        p.upstreamType = "clash";
        p.description = (name.empty() ? "" : (name + " - ")) + node.name;
        p.upstreamHost = node.server;
        p.upstreamPort = node.port;
        p.clashNodeName = node.name;
        p.groupName = group;
        p.clashConfig = ClashManager::GenerateNodeConfig(node, 0);
        p.listenPort = 0;
        p.enabled = true;
        p.autoCheck = true;
        p.clashSubscriptionId = subId;
        if (Database::Instance().AddProxyPort(p)) {
            imported++;
        }
    }
    Database::Instance().DeduplicateProxyPorts();
    ProxyServer::Instance().ReloadPorts();
    return { {"success", true}, {"importedCount", imported} };
}

nlohmann::json WebUIManager::HandleUpdateSubscription(int id) {
    int count = ClashManager::Instance().RefreshSubscription(id);
    if (count > 0) {
        ProxyServer::Instance().ReloadPorts();
        ProxyServer::Instance().TriggerCheck();
    }
    return { {"success", count >= 0}, {"updatedCount", count} };
}

nlohmann::json WebUIManager::HandleDeleteSubscription(int id) {
    Database::Instance().DeletePortsBySubscriptionId(id);
    bool ok = Database::Instance().DeleteSubscription(id);
    if (ok) ProxyServer::Instance().ReloadPorts();
    return { {"success", ok} };
}

nlohmann::json WebUIManager::HandleSaveSubscription(const nlohmann::json& p) {
    int id = p.value("id", 0);
    ClashSubscription sub;
    if (id > 0 && Database::Instance().GetSubscription(id, sub)) {
        if (p.contains("name")) sub.name = p["name"].get<std::string>();
        if (p.contains("url")) sub.url = p["url"].get<std::string>();
        if (p.contains("updateIntervalDays")) sub.updateIntervalDays = p["updateIntervalDays"].get<int>();
        if (p.contains("websiteUrl")) sub.websiteUrl = p["websiteUrl"].get<std::string>();
        if (p.contains("includeFilter")) sub.includeFilter = p["includeFilter"].get<std::string>();
        if (p.contains("excludeFilter")) sub.excludeFilter = p["excludeFilter"].get<std::string>();
        if (p.contains("resetCycleDays")) {
            int d = p["resetCycleDays"].get<int>();
            sub.resetCycleDays = (d <= 0 || d == 30) ? 0 : d;
        }
        if (p.contains("resetStartDate")) {
            std::string d = p["resetStartDate"].get<std::string>();
            if (!d.empty()) sub.resetStartDate = d;
        }
        bool ok = Database::Instance().UpdateSubscription(sub);
        if (ok) {
            // 保存后重新执行刷新以应用最新的筛选/排除规则与消重并拉取最新订阅信息
            ClashManager::Instance().RefreshSubscription(id);
            ProxyServer::Instance().ReloadPorts();
        }
        return { {"success", ok} };
    }
    return { {"success", false}, {"error", "订阅不存在"} };
}

nlohmann::json WebUIManager::HandleRefreshPortNode(int portId) {
    if (portId <= 0) {
        // 全量手动更新所有订阅与独立 Clash 节点
        auto subs = Database::Instance().GetAllSubscriptions();
        int totalUpdated = 0;
        for (const auto& sub : subs) {
            int count = ClashManager::Instance().RefreshSubscription(sub.id);
            if (count > 0) totalUpdated += count;
        }
        auto ports = Database::Instance().GetAllProxyPorts();
        for (const auto& p : ports) {
            if (p.upstreamType == "clash" && p.clashSubscriptionId <= 0 && !p.clashConfig.empty()) {
                if (ClashManager::Instance().IsRunning(p.id)) {
                    ClashManager::Instance().StopClash(p.id);
                }
                ClashManager::Instance().StartClash(p.id, p.clashConfig);
                totalUpdated++;
            }
        }
        ProxyServer::Instance().ReloadPorts();
        ProxyServer::Instance().TriggerCheck();
        return { {"success", true}, {"updatedCount", totalUpdated} };
    }

    ProxyPort port;
    if (!Database::Instance().GetProxyPort(portId, port)) {
        return { {"success", false}, {"error", "节点不存在"} };
    }

    if (port.upstreamType != "clash") {
        return { {"success", false}, {"error", "该节点非 Clash 内核节点"} };
    }

    int count = 0;
    if (port.clashSubscriptionId > 0) {
        count = ClashManager::Instance().RefreshSubscription(port.clashSubscriptionId);
    } else {
        // 独立自定义 Clash 节点，重启并重新测速
        if (ClashManager::Instance().IsRunning(port.id)) {
            ClashManager::Instance().StopClash(port.id);
        }
        if (!port.clashConfig.empty()) {
            ClashManager::Instance().StartClash(port.id, port.clashConfig);
        }
        count = 1;
    }

    ProxyServer::Instance().ReloadPorts();
    ProxyServer::Instance().TriggerCheck();
    return { {"success", count >= 0}, {"updatedCount", count} };
}

nlohmann::json WebUIManager::HandleGenerateSelfSignedCert(const std::string& domains) {
    std::string err;
    bool ok = SchannelSession::GenerateSelfSignedCert(domains, err);
    return {
        {"success", ok},
        {"error", err},
        {"cert_status", SchannelSession::GetCertStatusInfo()},
        {"cert_mode", "default"}
    };
}

nlohmann::json WebUIManager::HandleLoadCustomCert(const nlohmann::json& params) {
    bool isPfx = params.value("isPfx", false);
    std::string certPath = params.value("certPath", "");
    std::string keyPathOrPass = params.value("keyPathOrPass", "");
    std::string err;
    bool ok = false;
    if (isPfx) {
        ok = SchannelSession::LoadPfxFromFile(certPath, keyPathOrPass, err);
    } else {
        ok = SchannelSession::LoadCertAndKeyFromFiles(certPath, keyPathOrPass, err);
    }
    return {
        {"success", ok},
        {"error", err},
        {"cert_status", SchannelSession::GetCertStatusInfo()},
        {"cert_mode", ok ? "custom" : Database::Instance().GetConfig("https_cert_mode", "default")}
    };
}

nlohmann::json WebUIManager::HandleResetDefaultCert() {
    bool ok = SchannelSession::ResetToDefaultCert();
    return {
        {"success", ok},
        {"cert_status", SchannelSession::GetCertStatusInfo()},
        {"cert_mode", "default"}
    };
}

nlohmann::json WebUIManager::HandleExportCert() {
    const char* userProfile = std::getenv("USERPROFILE");
    std::string dest = "ProxyRelay.crt";
    if (userProfile && *userProfile) {
        std::string desktopPath = std::string(userProfile) + "\\Desktop\\ProxyRelay_CA.crt";
        if (SchannelSession::ExportCurrentCert(desktopPath)) {
            return { {"success", true}, {"path", desktopPath} };
        }
    }
    SchannelSession::ExportCurrentCert("ProxyRelay.crt");
    return { {"success", true}, {"path", "ProxyRelay.crt"} };
}

nlohmann::json WebUIManager::HandleGetChinaDirectSettings() {
    bool enabled = Database::Instance().GetConfig("china_direct_enabled", "1") == "1";
    bool cnDomains = Database::Instance().GetConfig("china_direct_cn_domains", "1") == "1";
    bool popularSites = Database::Instance().GetConfig("china_direct_popular_sites", "1") == "1";
    bool cnIps = Database::Instance().GetConfig("china_direct_ips", "1") == "1";
    bool lanIps = Database::Instance().GetConfig("china_direct_lan", "1") == "1";
    std::string custom = Database::Instance().GetConfig("china_direct_custom", "");

    std::string subUrl = RuleManager::Instance().GetChinaIpSubUrl();
    int subInterval = RuleManager::Instance().GetChinaIpSubIntervalDays();
    std::string lastUpdate = RuleManager::Instance().GetChinaIpLastUpdate();
    int cidrCount = RuleManager::Instance().GetChinaIpCidrCount();

    return {
        {"success", true},
        {"enabled", enabled},
        {"cn_domains", cnDomains},
        {"popular_sites", popularSites},
        {"cn_ips", cnIps},
        {"lan_ips", lanIps},
        {"custom_rules", custom},
        {"china_ip_sub_url", subUrl},
        {"china_ip_sub_interval", subInterval},
        {"china_ip_last_update", lastUpdate},
        {"china_ip_cidr_count", cidrCount}
    };
}

nlohmann::json WebUIManager::HandleSaveChinaDirectSettings(const nlohmann::json& params) {
    if (params.contains("enabled")) {
        Database::Instance().SetConfig("china_direct_enabled", params["enabled"].get<bool>() ? "1" : "0");
    }
    if (params.contains("cn_domains")) {
        Database::Instance().SetConfig("china_direct_cn_domains", params["cn_domains"].get<bool>() ? "1" : "0");
    }
    if (params.contains("popular_sites")) {
        Database::Instance().SetConfig("china_direct_popular_sites", params["popular_sites"].get<bool>() ? "1" : "0");
    }
    if (params.contains("cn_ips")) {
        Database::Instance().SetConfig("china_direct_ips", params["cn_ips"].get<bool>() ? "1" : "0");
    }
    if (params.contains("lan_ips")) {
        Database::Instance().SetConfig("china_direct_lan", params["lan_ips"].get<bool>() ? "1" : "0");
    }
    if (params.contains("custom_rules")) {
        Database::Instance().SetConfig("china_direct_custom", params["custom_rules"].get<std::string>());
    }
    if (params.contains("china_ip_sub_url")) {
        RuleManager::Instance().SetChinaIpSubUrl(params["china_ip_sub_url"].get<std::string>());
    }
    if (params.contains("china_ip_sub_interval")) {
        RuleManager::Instance().SetChinaIpSubIntervalDays(params["china_ip_sub_interval"].get<int>());
    }
    
    RuleManager::Instance().LoadChinaDirectConfig();
    RuleManager::Instance().ReloadRoutingRules();
    SharedStatusManager::Instance().NotifyRulesChanged();
    return { {"success", true} };
}

nlohmann::json WebUIManager::HandleUpdateChinaIpSubscription(const nlohmann::json& params) {
    std::string url = params.value("url", "");
    int count = 0;
    std::string error;
    bool ok = RuleManager::Instance().UpdateChinaIpSubscription(url, &count, &error);
    if (!ok) {
        return { {"success", false}, {"error", error.empty() ? "更新国内 IP 订阅失败" : error} };
    }
    return {
        {"success", true},
        {"count", count},
        {"last_update", RuleManager::Instance().GetChinaIpLastUpdate()},
        {"url", RuleManager::Instance().GetChinaIpSubUrl()}
    };
}

nlohmann::json WebUIManager::HandleExportConfig() {
    return Database::Instance().ExportConfig();
}

nlohmann::json WebUIManager::HandleImportConfig(const nlohmann::json& params) {
    bool overwrite = params.value("overwrite", false);
    nlohmann::json configObj = params.value("config", nlohmann::json::object());
    if (params.contains("config") && params["config"].is_string()) {
        try {
            configObj = nlohmann::json::parse(params["config"].get<std::string>());
        } catch (const std::exception& e) {
            return { {"success", false}, {"error", std::string("无效的 JSON 配置文件: ") + e.what()} };
        }
    }
    std::string errMsg;
    bool ok = Database::Instance().ImportConfig(configObj, overwrite, errMsg);
    if (ok) {
        RuleManager::Instance().ReloadRoutingRules();
        ProxyServer::Instance().ReloadPorts();
        return { {"success", true}, {"message", "配置已成功导入并生效"} };
    }
    return { {"success", false}, {"error", errMsg.empty() ? "导入配置失败" : errMsg} };
}

