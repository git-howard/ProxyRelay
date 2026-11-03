#include "WebServer.h"
#include "ProxyServer.h"
#include "TProxyServer.h"
#include "Database.h"
#include "TrafficMonitor.h"
#include "RealtimeConnectionManager.h"
#include "ConnectionLogger.h"
#include "Rules.h"
#include "UserManager.h"
#include "ClashManager.h"
#include "OpenSSLSession.h"
#include "Utils.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <filesystem>
#include <random>

namespace fs = std::filesystem;

WebServer& WebServer::Instance() {
    static WebServer instance;
    return instance;
}

WebServer::~WebServer() {
    Stop();
}

bool WebServer::Start(int port, const std::string& uiPath, const std::string& adminPassword) {
    if (running_.load()) return true;
    running_.store(true);
    uiFolderPath_ = uiPath;
    adminPassword_ = adminPassword;

    thread_ = std::thread(&WebServer::ServerThread, this, port);
    std::cout << "[WebServer] Management UI started on http://0.0.0.0:" << port << std::endl;
    return true;
}

void WebServer::Stop() {
    if (!running_.load()) return;
    running_.store(false);

    if (listenSock_ != INVALID_SOCKET) {
        shutdown(listenSock_, SHUT_RDWR);
        closesocket(listenSock_);
        listenSock_ = INVALID_SOCKET;
    }
    if (thread_.joinable()) thread_.join();
}

bool WebServer::VerifyPassword(const std::string& pwd) const {
    if (adminPassword_.empty()) return false;
    return pwd == adminPassword_;
}

std::string WebServer::GenerateSessionToken() {
    std::lock_guard<std::mutex> lock(authMutex_);
    static const char hexChars[] = "0123456789abcdef";
    std::string token;
    token.reserve(32);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 15);
    for (int i = 0; i < 32; ++i) {
        token += hexChars[dis(gen)];
    }
    validTokens_.insert(token);
    return token;
}

bool WebServer::ValidateSessionToken(const std::string& token) {
    if (adminPassword_.empty()) return true;
    if (token.empty()) return false;
    std::lock_guard<std::mutex> lock(authMutex_);
    return validTokens_.count(token) > 0;
}

void WebServer::InvalidateSessionToken(const std::string& token) {
    std::lock_guard<std::mutex> lock(authMutex_);
    validTokens_.erase(token);
}

void WebServer::ServerThread(int port) {
    listenSock_ = socket(AF_INET, SOCK_STREAM, 0);
    if (listenSock_ == INVALID_SOCKET) return;

    int opt = 1;
    setsockopt(listenSock_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(listenSock_, (sockaddr*)&addr, sizeof(addr)) != 0 || listen(listenSock_, 64) != 0) {
        closesocket(listenSock_);
        listenSock_ = INVALID_SOCKET;
        return;
    }

    while (running_.load()) {
        sockaddr_in clientAddr{};
        socklen_t clientLen = sizeof(clientAddr);
        SOCKET clientSock = accept(listenSock_, (sockaddr*)&clientAddr, &clientLen);
        if (clientSock == INVALID_SOCKET) {
            if (!running_.load()) break;
            continue;
        }

        std::thread(&WebServer::HandleClient, this, clientSock).detach();
    }
}

void WebServer::HandleClient(SOCKET clientSock) {
    // 设置读写超时 10 秒，防止慢速或断开连接阻塞工作线程
    struct timeval tv;
    tv.tv_sec = 10;
    tv.tv_usec = 0;
    setsockopt(clientSock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    setsockopt(clientSock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));

    std::string req;
    char buf[4096];
    size_t headerEnd = std::string::npos;
    while ((headerEnd = req.find("\r\n\r\n")) == std::string::npos) {
        int n = recv(clientSock, buf, sizeof(buf), 0);
        if (n <= 0) break;
        req.append(buf, n);
        if (req.length() > 65536) break; // 保护限制
    }

    if (headerEnd == std::string::npos) {
        closesocket(clientSock);
        return;
    }

    std::string headerPart = req.substr(0, headerEnd);
    std::string body = req.substr(headerEnd + 4);

    std::istringstream stream(headerPart);
    std::string method, path, proto;
    stream >> method >> path >> proto;

    // 处理 API 路由 POST /api/dispatch 或 /api
    if (method == "POST" && (path == "/api/dispatch" || path == "/api")) {
        // 大小写不敏感查找 Content-Length (支持空格/无空格)
        int contentLength = 0;
        std::string lowerHeaders = headerPart;
        for (auto& c : lowerHeaders) c = (char)std::tolower((unsigned char)c);
        size_t clPos = lowerHeaders.find("content-length:");
        if (clPos != std::string::npos) {
            size_t valStart = clPos + 15;
            while (valStart < lowerHeaders.length() && (lowerHeaders[valStart] == ' ' || lowerHeaders[valStart] == '\t')) {
                valStart++;
            }
            contentLength = std::atoi(lowerHeaders.c_str() + valStart);
        }

        // 提取 Authorization: Bearer <token>
        std::string headerToken;
        size_t authPos = lowerHeaders.find("authorization:");
        if (authPos != std::string::npos) {
            size_t valStart = authPos + 14;
            while (valStart < lowerHeaders.length() && (lowerHeaders[valStart] == ' ' || lowerHeaders[valStart] == '\t')) valStart++;
            size_t endOfLine = headerPart.find("\r\n", authPos);
            std::string authVal = headerPart.substr(valStart, (endOfLine == std::string::npos ? headerPart.length() : endOfLine) - valStart);
            if (authVal.rfind("Bearer ", 0) == 0 || authVal.rfind("bearer ", 0) == 0) {
                headerToken = authVal.substr(7);
            }
        }

        // 读取完整的 body，直到满足 contentLength 或出错
        while ((int)body.length() < contentLength) {
            int toRead = std::min((int)sizeof(buf), contentLength - (int)body.length());
            int n = recv(clientSock, buf, toRead, 0);
            if (n <= 0) break;
            body.append(buf, n);
        }

        nlohmann::json resp;
        int id = 0;
        std::string action;
        try {
            auto jsonReq = nlohmann::json::parse(body);
            id = jsonReq.value("id", 0);
            action = jsonReq.value("action", "");
            nlohmann::json data = jsonReq.value("data", nlohmann::json::object());
            if (data.empty() || !data.is_object()) {
                data = jsonReq;
            }

            std::string clientToken = jsonReq.value("token", "");
            if (clientToken.empty()) clientToken = headerToken;

            if (action == "auth_status") {
                bool authRequired = !adminPassword_.empty();
                bool authenticated = !authRequired || ValidateSessionToken(clientToken);
                resp["id"] = id;
                resp["action"] = action;
                resp["success"] = true;
                resp["data"] = {
                    {"authRequired", authRequired},
                    {"authenticated", authenticated}
                };
            } else if (action == "auth_login") {
                std::string pwd = data.value("password", "");
                if (adminPassword_.empty() || VerifyPassword(pwd)) {
                    std::string token = GenerateSessionToken();
                    resp["id"] = id;
                    resp["action"] = action;
                    resp["success"] = true;
                    resp["data"] = { {"token", token} };
                } else {
                    resp["id"] = id;
                    resp["action"] = action;
                    resp["success"] = false;
                    resp["error"] = "管理密码错误，请重新输入";
                }
            } else if (action == "auth_logout") {
                if (!clientToken.empty()) {
                    InvalidateSessionToken(clientToken);
                }
                resp["id"] = id;
                resp["action"] = action;
                resp["success"] = true;
                resp["data"] = nlohmann::json::object();
            } else {
                // 鉴权检查：如果设置了管理密码，且 token 未通过校验，直接返回 401
                if (!adminPassword_.empty() && !ValidateSessionToken(clientToken)) {
                    resp["id"] = id;
                    resp["action"] = action;
                    resp["success"] = false;
                    resp["authRequired"] = true;
                    resp["error"] = "unauthorized";

                    std::string respStr = resp.dump();
                    std::ostringstream ss;
                    ss << "HTTP/1.1 401 Unauthorized\r\n"
                       << "Content-Type: application/json; charset=utf-8\r\n"
                       << "Access-Control-Allow-Origin: *\r\n"
                       << "Access-Control-Allow-Headers: *\r\n"
                       << "Content-Length: " << respStr.length() << "\r\n\r\n"
                       << respStr;
                    std::string out = ss.str();
                    send(clientSock, out.c_str(), out.length(), 0);
                    closesocket(clientSock);
                    return;
                }

                nlohmann::json result = DispatchApi(action, data);
                resp["id"] = id;
                resp["action"] = action;
                resp["success"] = true;
                resp["data"] = result;
            }
        } catch (const std::exception& e) {
            resp["id"] = id;
            resp["action"] = action;
            resp["success"] = false;
            resp["error"] = e.what();
        }

        std::string respStr = resp.dump();
        std::ostringstream ss;
        ss << "HTTP/1.1 200 OK\r\n"
           << "Content-Type: application/json; charset=utf-8\r\n"
           << "Access-Control-Allow-Origin: *\r\n"
           << "Access-Control-Allow-Headers: *\r\n"
           << "Content-Length: " << respStr.length() << "\r\n\r\n"
           << respStr;
        std::string out = ss.str();
        send(clientSock, out.c_str(), out.length(), 0);
        closesocket(clientSock);
        return;
    }

    // 处理 OPTIONS 跨域预检
    if (method == "OPTIONS") {
        const char* optResp = "HTTP/1.1 204 No Content\r\n"
                              "Access-Control-Allow-Origin: *\r\n"
                              "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
                              "Access-Control-Allow-Headers: *\r\n\r\n";
        send(clientSock, optResp, strlen(optResp), 0);
        closesocket(clientSock);
        return;
    }

    // 处理静态页面 GET 请求
    if (path == "/" || path == "/index.html") {
        std::string html = ReadUiFile("index.html");
        if (html.empty()) {
            const char* notFound = "HTTP/1.1 404 Not Found\r\nContent-Length: 13\r\n\r\n404 Not Found";
            send(clientSock, notFound, strlen(notFound), 0);
        } else {
            std::ostringstream ss;
            ss << "HTTP/1.1 200 OK\r\n"
               << "Content-Type: text/html; charset=utf-8\r\n"
               << "Cache-Control: no-cache, no-store, must-revalidate\r\n"
               << "Pragma: no-cache\r\n"
               << "Expires: 0\r\n"
               << "Content-Length: " << html.length() << "\r\n\r\n"
               << html;
            std::string out = ss.str();
            send(clientSock, out.c_str(), out.length(), 0);
        }
        closesocket(clientSock);
        return;
    }

    const char* notFound = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
    send(clientSock, notFound, strlen(notFound), 0);
    closesocket(clientSock);
}

std::string WebServer::ReadUiFile(const std::string& filename) {
    std::vector<std::string> searchPaths = {
        uiFolderPath_ + "/" + filename,
        "ui/" + filename,
        "/usr/share/proxyrelay/ui/" + filename,
        "../ui/" + filename
    };

    for (const auto& p : searchPaths) {
        if (fs::exists(p)) {
            std::ifstream f(p, std::ios::binary);
            if (f.is_open()) {
                return std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
            }
        }
    }
    return "";
}

nlohmann::json WebServer::DispatchApi(const std::string& action, const nlohmann::json& params) {
    if (action == "get_status") {
        auto traffic = TrafficMonitor::Instance().GetCurrentData();
        bool isRunning = ProxyServer::Instance().IsRunning();
        bool tproxyRunning = TProxyServer::Instance().IsRunning();
        bool tproxyEnabled = Database::Instance().GetConfig("tproxy_enabled", "0") == "1";
        int tproxyPort = TProxyServer::Instance().GetPort() > 0 ? TProxyServer::Instance().GetPort()
            : std::atoi(Database::Instance().GetConfig("tproxy_port", "12345").c_str());
        int activeConns = (int)RealtimeConnectionManager::Instance().GetConnectionsSnapshot().size();
        int64_t uptimeSec = isRunning ? ProxyServer::Instance().GetUptime() : 0;
        return {
            {"running", isRunning},
            {"isRunning", isRunning},
            {"tproxy_running", tproxyRunning},
            {"tproxyRunning", tproxyRunning},
            {"tproxy_enabled", tproxyEnabled},
            {"tproxyEnabled", tproxyEnabled},
            {"tproxy_port", tproxyPort},
            {"tproxyPort", tproxyPort},
            {"upload_speed", traffic.uploadSpeed},
            {"uploadSpeed", traffic.uploadSpeed},
            {"download_speed", traffic.downloadSpeed},
            {"downloadSpeed", traffic.downloadSpeed},
            {"total_upload", traffic.totalUpload},
            {"totalUpload", traffic.totalUpload},
            {"total_download", traffic.totalDownload},
            {"totalDownload", traffic.totalDownload},
            {"active_connections", activeConns},
            {"activeConnections", activeConns},
            {"uptime", uptimeSec},
            {"uptime_seconds", uptimeSec},
            {"uptimeSeconds", uptimeSec},
            {"version", "v1.0.0"}
        };
    } else if (action == "toggle_service") {
        bool start = params.value("start", true);
        if (start) {
            ProxyServer::Instance().Start();
            Utils::ExecCmd("uci -q set proxyrelay.global.enabled=1 && uci -q commit proxyrelay");
            if (Database::Instance().GetConfig("tproxy_enabled", "0") == "1") {
                int tproxyPort = std::atoi(Database::Instance().GetConfig("tproxy_port", "12345").c_str());
                TProxyServer::Instance().Start(tproxyPort);
                Utils::ExecCmd("sh /usr/share/proxyrelay/firewall.include reload >/dev/null 2>&1 &");
            }
        } else {
            ProxyServer::Instance().Stop();
            TProxyServer::Instance().Stop();
            Utils::ExecCmd("sh /usr/share/proxyrelay/firewall.include stop >/dev/null 2>&1 &");
            Utils::ExecCmd("uci -q set proxyrelay.global.enabled=0 && uci -q commit proxyrelay");
        }
        return { 
            {"success", true}, 
            {"running", start},
            {"isRunning", start}
        };
    } else if (action == "get_ports") {
        auto ports = Database::Instance().GetAllProxyPorts();
        nlohmann::json arr = nlohmann::json::array();
        for (const auto& p : ports) {
            arr.push_back({
                {"id", p.id},
                {"listenPort", p.listenPort},
                {"upstreamType", p.upstreamType},
                {"upstreamHost", p.upstreamHost},
                {"upstreamPort", p.upstreamPort},
                {"enabled", p.enabled},
                {"autoCheck", p.autoCheck},
                {"description", p.description},
                {"priority", p.priority},
                {"groupName", p.groupName},
                {"isAvailable", true}
            });
        }
        return arr;
    } else if (action == "save_port") {
        ProxyPort p;
        p.id = params.value("id", 0);
        p.listenPort = params.value("listenPort", 0);
        p.upstreamType = params.value("upstreamType", "http");
        p.upstreamHost = params.value("upstreamHost", "");
        p.upstreamPort = params.value("upstreamPort", 0);
        p.upstreamUser = params.value("upstreamUser", "");
        p.upstreamPass = params.value("upstreamPass", "");
        p.enabled = params.value("enabled", true);
        p.autoCheck = params.value("autoCheck", true);
        p.description = params.value("description", "");
        p.priority = params.value("priority", 0);
        p.groupName = params.value("groupName", "默认");
        bool ok = Database::Instance().SaveProxyPort(p);
        if (ok) ProxyServer::Instance().ReloadPorts();
        return { {"success", ok} };
    } else if (action == "delete_port") {
        int id = params.value("id", 0);
        bool ok = Database::Instance().DeleteProxyPort(id);
        if (ok) ProxyServer::Instance().ReloadPorts();
        return { {"success", ok} };
    } else if (action == "toggle_port") {
        int id = params.value("id", 0);
        bool enabled = params.value("enabled", true);
        bool ok = Database::Instance().ToggleProxyPort(id, enabled);
        if (ok) ProxyServer::Instance().ReloadPorts();
        return { {"success", ok} };
    } else if (action == "move_port_up") {
        std::string grp = params.value("group", "");
        bool ok = Database::Instance().MoveProxyPortUp(params.value("id", 0), grp);
        return { {"success", ok} };
    } else if (action == "move_port_down") {
        std::string grp = params.value("group", "");
        bool ok = Database::Instance().MoveProxyPortDown(params.value("id", 0), grp);
        return { {"success", ok} };
    } else if (action == "rename_port_group") {
        bool ok = Database::Instance().RenamePortGroup(params.value("oldName", ""), params.value("newName", ""));
        return { {"success", ok} };
    } else if (action == "get_port_groups") {
        auto groups = Database::Instance().GetAllPortGroups();
        return { {"success", true}, {"groups", groups} };
    } else if (action == "get_rules") {
        auto rules = Database::Instance().GetAllRoutingRules();
        nlohmann::json arr = nlohmann::json::array();
        for (const auto& r : rules) {
            arr.push_back({
                {"id", r.id},
                {"priority", r.priority},
                {"matchType", r.matchType},
                {"matchValue", r.matchValue},
                {"proxyId", r.proxyId},
                {"targetGroup", r.targetGroup},
                {"description", r.description},
                {"enabled", r.enabled},
                {"isFallback", r.isFallback}
            });
        }
        return arr;
    } else if (action == "save_rule") {
        RoutingRule r;
        r.id = params.value("id", 0);
        r.priority = params.value("priority", 0);
        r.matchType = params.value("matchType", "domain");
        r.matchValue = params.value("matchValue", "");
        r.proxyId = params.value("proxyId", 0);
        r.targetGroup = params.value("targetGroup", "");
        r.description = params.value("description", "");
        r.enabled = params.value("enabled", true);
        r.isFallback = params.value("isFallback", false);
        if (r.id > 0 && r.priority <= 0) {
            auto all = Database::Instance().GetAllRoutingRules();
            for (const auto& item : all) {
                if (item.id == r.id) {
                    r.priority = item.priority;
                    break;
                }
            }
        }
        bool ok = Database::Instance().SaveRoutingRule(r);
        if (ok) RuleManager::Instance().ReloadRoutingRules();
        return { {"success", ok} };
    } else if (action == "delete_rule") {
        int id = params.value("id", 0);
        bool ok = Database::Instance().DeleteRoutingRule(id);
        if (ok) RuleManager::Instance().ReloadRoutingRules();
        return { {"success", ok} };
    } else if (action == "toggle_rule") {
        int id = params.value("id", 0);
        bool enabled = params.value("enabled", true);
        bool ok = Database::Instance().ToggleRoutingRule(id, enabled);
        if (ok) RuleManager::Instance().ReloadRoutingRules();
        return { {"success", ok} };
    } else if (action == "move_rule_up") {
        bool ok = Database::Instance().MoveRoutingRuleUp(params.value("id", 0));
        if (ok) RuleManager::Instance().ReloadRoutingRules();
        return { {"success", ok} };
    } else if (action == "move_rule_down") {
        bool ok = Database::Instance().MoveRoutingRuleDown(params.value("id", 0));
        if (ok) RuleManager::Instance().ReloadRoutingRules();
        return { {"success", ok} };
    } else if (action == "get_users") {
        auto users = Database::Instance().GetAllUsers();
        nlohmann::json arr = nlohmann::json::array();
        for (const auto& u : users) {
            int64_t monthlyUsed = Database::Instance().GetUserMonthlyTraffic(u.id);
            int64_t totalUsed = Database::Instance().GetUserTotalTraffic(u.id);
            arr.push_back({
                {"id", u.id},
                {"username", u.username},
                {"hasPassword", !u.password.empty()},
                {"allowedIPs", u.allowedIPs},
                {"monthlyLimit", u.monthlyLimit},
                {"monthlyTrafficLimit", u.monthlyLimit},
                {"monthlyUsed", monthlyUsed},
                {"totalUsed", totalUsed},
                {"enabled", u.enabled},
                {"remark", u.remark},
                {"priority", u.priority}
            });
        }
        return arr;
    } else if (action == "save_user") {
        UserInfo u;
        u.id = params.value("id", 0);
        u.username = params.value("username", "");
        u.password = params.value("password", "");
        bool clearPassword = params.value("clearPassword", false);
        u.allowedIPs = params.value("allowedIPs", "*");
        u.monthlyLimit = params.value("monthlyLimit", (int64_t)0);
        u.dailyLimit = params.value("dailyLimit", (int64_t)0);
        u.enabled = params.value("enabled", true);
        u.remark = params.value("remark", "");
        u.priority = params.value("priority", 0);

        if (u.id > 0) {
            UserInfo existing;
            if (Database::Instance().GetUserById(u.id, existing)) {
                if (clearPassword) {
                    u.password = "";
                } else if (u.password.empty()) {
                    u.password = existing.password;
                }
                if (u.allowedTargets.empty() || u.allowedTargets == "*") {
                    u.allowedTargets = existing.allowedTargets;
                }
                if (u.remark.empty()) u.remark = existing.remark;
                u.expiryDate = existing.expiryDate;
                if (u.priority <= 0) {
                    u.priority = existing.priority;
                }
            }
        }

        // 用户密码是可选项，如不输入密码则需要输入客户端IP规则
        if (u.password.empty()) {
            if (u.allowedIPs.empty() || u.allowedIPs == "*") {
                return { {"success", false}, {"error", "用户密码为可选项；如不输入密码，则必须输入具体的客户端IP规则（不支持留空或*）"} };
            }
        }

        bool ok = Database::Instance().SaveUser(u);
        if (ok) UserManager::Instance().InvalidateCache();
        return { {"success", ok} };
    } else if (action == "delete_user") {
        int id = params.value("id", 0);
        bool ok = Database::Instance().DeleteUser(id);
        if (ok) UserManager::Instance().InvalidateCache();
        return { {"success", ok} };
    } else if (action == "toggle_user") {
        bool ok = Database::Instance().ToggleUser(params.value("id", 0), params.value("enabled", true));
        if (ok) UserManager::Instance().InvalidateCache();
        return { {"success", ok} };
    } else if (action == "move_user_up") {
        bool ok = Database::Instance().MoveUserUp(params.value("id", 0));
        if (ok) UserManager::Instance().InvalidateCache();
        return { {"success", ok} };
    } else if (action == "move_user_down") {
        bool ok = Database::Instance().MoveUserDown(params.value("id", 0));
        if (ok) UserManager::Instance().InvalidateCache();
        return { {"success", ok} };
    } else if (action == "reset_user_traffic") {
        bool ok = Database::Instance().ResetUserTraffic(params.value("id", 0));
        return { {"success", ok} };
    } else if (action == "get_blacklist" || action == "get_security_lists") {
        auto items = Database::Instance().GetBlacklist();
        nlohmann::json blackArr = nlohmann::json::array();
        nlohmann::json autoBanArr = nlohmann::json::array();
        std::string nowStr = Utils::GetCurrentDateTime();

        for (const auto& b : items) {
            bool isAuto = (b.reason.find("自动封禁") != std::string::npos);
            if (isAuto) {
                bool isExpired = (!b.bannedUntil.empty() && b.bannedUntil <= nowStr);
                autoBanArr.push_back({
                    {"id", b.id},
                    {"ip", b.ip},
                    {"reason", b.reason},
                    {"failCount", b.failCount},
                    {"bannedUntil", b.bannedUntil},
                    {"createdAt", b.createdAt},
                    {"isExpired", isExpired}
                });
            } else {
                blackArr.push_back({
                    {"id", b.id},
                    {"ip", b.ip},
                    {"remark", b.reason},
                    {"createdAt", b.createdAt}
                });
            }
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
        bool ok = Database::Instance().AddBlacklist(ip, remark);
        return { {"success", ok} };
    } else if (action == "delete_blacklist") {
        int id = params.value("id", 0);
        std::string ip = params.value("ip", "");
        bool ok = false;
        if (id > 0) ok = Database::Instance().RemoveBlacklistById(id);
        else if (!ip.empty()) ok = Database::Instance().RemoveBlacklist(ip);
        return { {"success", ok} };
    } else if (action == "remove_autoban" || action == "unban_ip") {
        int id = params.value("id", 0);
        std::string ip = params.value("ip", "");
        bool ok = false;
        if (id > 0) ok = Database::Instance().RemoveBlacklistById(id);
        else if (!ip.empty()) ok = Database::Instance().RemoveBlacklist(ip);
        return { {"success", ok} };
    } else if (action == "clear_autobans") {
        bool ok = Database::Instance().ClearAutoBans();
        return { {"success", ok} };
    } else if (action == "get_ban_policy") {
        auto policy = Database::Instance().GetBanPolicy();
        return {
            {"enabled", policy.enabled},
            {"windowMinutes", policy.windowMinutes},
            {"maxFailures", policy.maxFailures},
            {"banMinutes", policy.banMinutes}
        };
    } else if (action == "save_ban_policy") {
        Database::BanPolicy policy;
        policy.enabled = params.value("enabled", true);
        policy.windowMinutes = params.value("windowMinutes", 5);
        policy.maxFailures = params.value("maxFailures", 10);
        policy.banMinutes = params.value("banMinutes", 60);
        bool ok = Database::Instance().SaveBanPolicy(policy);
        return { {"success", ok} };
    } else if (action == "get_connections") {
        auto conns = RealtimeConnectionManager::Instance().GetConnectionsSnapshot();
        nlohmann::json arr = nlohmann::json::array();
        for (const auto& c : conns) {
            arr.push_back({
                {"id", c.id},
                {"timestamp", c.timestamp},
                {"startTime", c.timestamp},
                {"username", c.username},
                {"clientIP", c.clientIP},
                {"protocol", c.protocol.empty() ? "TCP" : c.protocol},
                {"inboundType", c.inboundType.empty() ? "HTTP" : c.inboundType},
                {"targetHost", c.targetHost},
                {"targetPort", c.targetPort},
                {"proxyDesc", c.proxyDesc},
                {"uploadBytes", c.uploadBytes},
                {"downloadBytes", c.downloadBytes},
                {"active", c.active}
            });
        }
        return arr;
    } else if (action == "close_connection") {
        uint64_t id = params.value("connId", (uint64_t)0);
        RealtimeConnectionManager::Instance().CloseConnection(id);
        return { {"success", true} };
    } else if (action == "get_logs") {
        int limit = params.value("limit", 200);
        auto logs = ConnectionLogger::Instance().GetRecentLogs(limit);
        nlohmann::json arr = nlohmann::json::array();
        for (const auto& l : logs) {
            arr.push_back({
                {"timestamp", l.timestamp},
                {"username", l.username},
                {"clientIP", l.clientIP},
                {"protocol", l.protocol.empty() ? "TCP" : l.protocol},
                {"inboundType", l.inboundType.empty() ? "HTTP" : l.inboundType},
                {"targetHost", l.targetHost},
                {"targetPort", l.targetPort},
                {"action", l.action},
                {"proxyDesc", l.proxyDesc}
            });
        }
        return arr;
    } else if (action == "clear_logs") {
        ConnectionLogger::Instance().Clear();
        return { {"success", true} };
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
        auto list = Database::Instance().GetTrafficTrend(mode, count, userId);
        nlohmann::json histArr = nlohmann::json::array();
        int64_t totalUp = 0, totalDown = 0;
        for (const auto& item : list) {
            totalUp += item.uploadBytes;
            totalDown += item.downloadBytes;
            histArr.push_back({
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
        return {
            {"mode", mode},
            {"count", count},
            {"days", count},
            {"userId", userId},
            {"totalUpload", totalUp},
            {"totalDownload", totalDown},
            {"totalBytes", totalBytes},
            {"average", avg},
            {"dailyAverage", avg},
            {"history", histArr}
        };
    } else if (action == "get_node_traffic_analysis") {
        int portId = params.value("portId", -1);
        std::string mode = params.value("mode", "30days");
        int year = params.value("year", 0);
        if (mode == "annual") {
            auto hist = Database::Instance().GetPortAnnualTrafficHistory(year, portId);
            nlohmann::json histArr = nlohmann::json::array();
            int64_t totalUp = 0, totalDown = 0;
            for (const auto& item : hist) {
                totalUp += item.uploadBytes;
                totalDown += item.downloadBytes;
                histArr.push_back({
                    {"month", item.month},
                    {"upload", item.uploadBytes},
                    {"download", item.downloadBytes},
                    {"total", item.totalBytes}
                });
            }
            return {
                {"year", year},
                {"totalUpload", totalUp},
                {"totalDownload", totalDown},
                {"totalBytes", totalUp + totalDown},
                {"history", histArr}
            };
        } else {
            auto hist = Database::Instance().GetPortDailyTrafficHistory(30, portId);
            nlohmann::json histArr = nlohmann::json::array();
            int64_t totalUp = 0, totalDown = 0;
            for (const auto& item : hist) {
                totalUp += item.uploadBytes;
                totalDown += item.downloadBytes;
                histArr.push_back({
                    {"date", item.date},
                    {"upload", item.uploadBytes},
                    {"download", item.downloadBytes},
                    {"total", item.totalBytes}
                });
            }
            return {
                {"days", 30},
                {"totalUpload", totalUp},
                {"totalDownload", totalDown},
                {"totalBytes", totalUp + totalDown},
                {"history", histArr}
            };
        }
    } else if (action == "get_china_direct_settings") {
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
    } else if (action == "save_china_direct_settings") {
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
        return { {"success", true} };
    } else if (action == "update_china_ip_subscription") {
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
    } else if (action == "get_settings") {
        nlohmann::json res = {
            {"auto_proxy_port", Database::Instance().GetConfig("auto_proxy_port", "1080")},
            {"relay_buffer_size_kb", Database::Instance().GetConfig("relay_buffer_size_kb", "64")},
            {"inbound_proxy_type", Database::Instance().GetConfig("inbound_proxy_type", "all")},
            {"tproxy_enabled", Database::Instance().GetConfig("tproxy_enabled", "0")},
            {"tproxy_port", Database::Instance().GetConfig("tproxy_port", "12345")},
            {"tproxy_running", TProxyServer::Instance().IsRunning()},
            {"cert_status", OpenSSLSession::GetCertStatusInfo()},
            {"cert_mode", Database::Instance().GetConfig("https_cert_mode", "self_signed")},
            {"cert_source", Database::Instance().GetConfig("https_cert_source", "upload")},
            {"cert_file", Database::Instance().GetConfig("https_cert_file", "")},
            {"key_file", Database::Instance().GetConfig("https_key_file", "")},
            {"cert_url", Database::Instance().GetConfig("https_cert_url", "")},
            {"key_url", Database::Instance().GetConfig("https_key_url", "")},
            {"cert_domains", Database::Instance().GetConfig("cert_domains", "localhost,127.0.0.1,::1,ProxyRelay")},
            {"log_retention_days", Database::Instance().GetConfig("log_retention_days", "30")},
            {"traffic_retention_days", Database::Instance().GetConfig("traffic_retention_days", "365")},
            {"port_traffic_retention_days", Database::Instance().GetConfig("port_traffic_retention_days", "60")},
            {"has_admin_password", !adminPassword_.empty()}
        };

        // 当前数据占用量统计
        int64_t logBytes = 0;
        int logCount = 0;
        ConnectionLogger::Instance().GetStorageInfo(logBytes, logCount);
        res["log_storage_bytes"] = logBytes;
        res["log_storage_count"] = logCount;
        res["log_storage_desc"] = (logCount > 0) ? ("当前占用: " + Utils::FormatBytes(logBytes) + " (" + std::to_string(logCount) + "条记录)") : "当前占用: 0 B";

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
        return res;
    } else if (action == "save_settings") {
        if (params.contains("auto_proxy_port")) Database::Instance().SetConfig("auto_proxy_port", params["auto_proxy_port"].get<std::string>());
        if (params.contains("relay_buffer_size_kb")) Database::Instance().SetConfig("relay_buffer_size_kb", params["relay_buffer_size_kb"].get<std::string>());
        if (params.contains("inbound_proxy_type")) Database::Instance().SetConfig("inbound_proxy_type", params["inbound_proxy_type"].get<std::string>());
        if (params.contains("log_retention_days")) {
            std::string d = params["log_retention_days"].is_string() ? params["log_retention_days"].get<std::string>() : std::to_string(params["log_retention_days"].get<int>());
            Database::Instance().SetConfig("log_retention_days", d);
        }
        if (params.contains("traffic_retention_days")) {
            std::string d = params["traffic_retention_days"].is_string() ? params["traffic_retention_days"].get<std::string>() : std::to_string(params["traffic_retention_days"].get<int>());
            Database::Instance().SetConfig("traffic_retention_days", d);
            Database::Instance().CleanOldTrafficRecords();
        }
        if (params.contains("port_traffic_retention_days")) {
            std::string d = params["port_traffic_retention_days"].is_string() ? params["port_traffic_retention_days"].get<std::string>() : std::to_string(params["port_traffic_retention_days"].get<int>());
            Database::Instance().SetConfig("port_traffic_retention_days", d);
            Database::Instance().CleanOldTrafficRecords();
        }

        bool tproxyChanged = false;
        std::string oldTproxyEnabled = Database::Instance().GetConfig("tproxy_enabled", "0");
        std::string newTproxyEnabled = oldTproxyEnabled;
        std::string oldTproxyPort = Database::Instance().GetConfig("tproxy_port", "12345");
        std::string newTproxyPort = oldTproxyPort;

        if (params.contains("tproxy_enabled")) {
            if (params["tproxy_enabled"].is_string()) {
                newTproxyEnabled = params["tproxy_enabled"].get<std::string>();
            } else if (params["tproxy_enabled"].is_boolean()) {
                newTproxyEnabled = params["tproxy_enabled"].get<bool>() ? "1" : "0";
            } else if (params["tproxy_enabled"].is_number()) {
                newTproxyEnabled = params["tproxy_enabled"].get<int>() ? "1" : "0";
            }
            Database::Instance().SetConfig("tproxy_enabled", newTproxyEnabled);
            Utils::ExecCmd("uci -q set proxyrelay.global.tproxy_enabled=" + newTproxyEnabled + " && uci -q commit proxyrelay");
            if (newTproxyEnabled != oldTproxyEnabled) tproxyChanged = true;
        }

        if (params.contains("tproxy_port")) {
            if (params["tproxy_port"].is_string()) {
                newTproxyPort = params["tproxy_port"].get<std::string>();
            } else if (params["tproxy_port"].is_number()) {
                newTproxyPort = std::to_string(params["tproxy_port"].get<int>());
            }
            Database::Instance().SetConfig("tproxy_port", newTproxyPort);
            Utils::ExecCmd("uci -q set proxyrelay.global.tproxy_port=" + newTproxyPort + " && uci -q commit proxyrelay");
            if (newTproxyPort != oldTproxyPort) tproxyChanged = true;
        }

        if (tproxyChanged || (newTproxyEnabled == "1" && !TProxyServer::Instance().IsRunning())) {
            int port = std::atoi(newTproxyPort.c_str());
            if (newTproxyEnabled == "1" && port > 0) {
                TProxyServer::Instance().Stop();
                TProxyServer::Instance().Start(port);
                Utils::ExecCmd("sh /usr/share/proxyrelay/firewall.include reload >/dev/null 2>&1 &");
            } else {
                TProxyServer::Instance().Stop();
                Utils::ExecCmd("sh /usr/share/proxyrelay/firewall.include stop >/dev/null 2>&1 &");
            }
        }

        ProxyServer::Instance().ReloadPorts();
        return { 
            {"success", true},
            {"tproxy_enabled", newTproxyEnabled},
            {"tproxy_port", newTproxyPort},
            {"tproxy_running", TProxyServer::Instance().IsRunning()}
        };
    } else if (action == "save_admin_password") {
        std::string newPwd = params.value("password", "");
        adminPassword_ = newPwd;
        Database::Instance().SetConfig("admin_password", newPwd);
        std::string escaped = "";
        for (char c : newPwd) {
            if (c == '\'') escaped += "'\\''";
            else escaped += c;
        }
        Utils::ExecCmd("uci -q set proxyrelay.global.password='" + escaped + "' && uci -q commit proxyrelay");
        std::string newToken = "";
        if (!newPwd.empty()) {
            newToken = GenerateSessionToken();
        }
        return {
            {"success", true},
            {"token", newToken},
            {"has_admin_password", !newPwd.empty()},
            {"auth_required", !newPwd.empty()}
        };
    } else if (action == "generate_self_signed_cert") {
        std::string domains = params.value("domains", "");
        Database::Instance().SetConfig("cert_domains", domains);
        Database::Instance().SetConfig("https_cert_mode", "self_signed");
        OpenSSLSession::GenerateSelfSignedCert("", "", domains);
        return {
            {"success", true},
            {"cert_status", OpenSSLSession::GetCertStatusInfo()},
            {"cert_mode", "self_signed"}
        };
    } else if (action == "reset_default_cert") {
        bool ok = OpenSSLSession::ResetToDefaultCert();
        if (ok) {
            Database::Instance().SetConfig("https_cert_mode", "self_signed");
        }
        return {
            {"success", ok},
            {"cert_status", OpenSSLSession::GetCertStatusInfo()},
            {"cert_mode", "self_signed"}
        };
    } else if (action == "export_cert") {
        std::string certPath = OpenSSLSession::GetActiveCertPath();
        std::ifstream file(certPath, std::ios::binary);
        if (!file.is_open()) {
            return { {"success", false}, {"error", "无法读取当前生效的证书文件"} };
        }
        std::ostringstream ss;
        ss << file.rdbuf();
        return {
            {"success", true},
            {"filename", "ProxyRelay.crt"},
            {"content", ss.str()}
        };
    } else if (action == "load_custom_cert") {
        std::string sourceType = params.value("source_type", "local");
        std::string targetDir = OpenSSLSession::GetDefaultCertDir();
        std::string targetCert = targetDir + "/custom_cert.crt";
        std::string targetKey = targetDir + "/custom_key.key";
        std::string err;

        if (sourceType == "upload") {
            std::string certContent = params.value("cert_content", "");
            std::string keyContent = params.value("key_content", "");
            if (certContent.empty()) return { {"success", false}, {"error", "公钥证书内容不能为空"} };
            if (keyContent.empty()) return { {"success", false}, {"error", "私钥内容不能为空"} };

            try {
                fs::create_directories(targetDir);
                std::ofstream fCert(targetCert, std::ios::binary);
                if (!fCert.is_open()) return { {"success", false}, {"error", "写入公钥证书失败，请检查目录权限"} };
                fCert << certContent;
                fCert.close();

                std::ofstream fKey(targetKey, std::ios::binary);
                if (!fKey.is_open()) return { {"success", false}, {"error", "写入私钥失败，请检查目录权限"} };
                fKey << keyContent;
                fKey.close();
            } catch (const std::exception& e) {
                return { {"success", false}, {"error", std::string("证书文件写入异常: ") + e.what()} };
            }

            if (!OpenSSLSession::ReloadCertificates(targetCert, targetKey, err)) {
                return { {"success", false}, {"error", err} };
            }

            Database::Instance().SetConfig("https_cert_mode", "custom");
            Database::Instance().SetConfig("https_cert_source", "upload");
            Database::Instance().SetConfig("https_cert_file", targetCert);
            Database::Instance().SetConfig("https_key_file", targetKey);
            return {
                {"success", true},
                {"cert_status", OpenSSLSession::GetCertStatusInfo()},
                {"cert_mode", "custom"}
            };
        } else if (sourceType == "url") {
            std::string certUrl = params.value("cert_url", "");
            std::string keyUrl = params.value("key_url", "");
            if (certUrl.empty()) return { {"success", false}, {"error", "公钥证书下载 URL 不能为空"} };
            if (keyUrl.empty()) return { {"success", false}, {"error", "私钥下载 URL 不能为空"} };

            auto isSafeUrl = [](const std::string& url) {
                if (url.rfind("http://", 0) != 0 && url.rfind("https://", 0) != 0) return false;
                for (char c : url) {
                    if (c == '\'' || c == '"' || c == '`' || c == ';' || c == '$' || c == '|' || c == '&' || c == '\\' || c == ' ' || c == '\n' || c == '\r') {
                        return false;
                    }
                }
                return true;
            };
            if (!isSafeUrl(certUrl) || !isSafeUrl(keyUrl)) {
                return { {"success", false}, {"error", "证书下载 URL 包含非法字符或不是合法的 http/https 地址"} };
            }

            std::string tmpCert = "/tmp/downloaded_cert_" + std::to_string(Utils::GetCurrentTimestamp()) + ".crt";
            std::string tmpKey = "/tmp/downloaded_key_" + std::to_string(Utils::GetCurrentTimestamp()) + ".key";

            std::string cmdCert = "wget -q --timeout=15 --no-check-certificate -O '" + tmpCert + "' '" + certUrl + "' 2>/dev/null";
            int retCert = std::system(cmdCert.c_str());
            if (retCert != 0 || !fs::exists(tmpCert) || fs::file_size(tmpCert) == 0) {
                if (fs::exists(tmpCert)) fs::remove(tmpCert);
                return { {"success", false}, {"error", "从 URL 下载公钥证书失败，请检查 URL 是否有效且可访问"} };
            }

            std::string cmdKey = "wget -q --timeout=15 --no-check-certificate -O '" + tmpKey + "' '" + keyUrl + "' 2>/dev/null";
            int retKey = std::system(cmdKey.c_str());
            if (retKey != 0 || !fs::exists(tmpKey) || fs::file_size(tmpKey) == 0) {
                if (fs::exists(tmpCert)) fs::remove(tmpCert);
                if (fs::exists(tmpKey)) fs::remove(tmpKey);
                return { {"success", false}, {"error", "从 URL 下载私钥失败，请检查 URL 是否有效且可访问"} };
            }

            if (!OpenSSLSession::ReloadCertificates(tmpCert, tmpKey, err)) {
                if (fs::exists(tmpCert)) fs::remove(tmpCert);
                if (fs::exists(tmpKey)) fs::remove(tmpKey);
                return { {"success", false}, {"error", err} };
            }

            try {
                fs::create_directories(targetDir);
                fs::copy_file(tmpCert, targetCert, fs::copy_options::overwrite_existing);
                fs::copy_file(tmpKey, targetKey, fs::copy_options::overwrite_existing);
                fs::remove(tmpCert);
                fs::remove(tmpKey);
            } catch (...) {}

            OpenSSLSession::ReloadCertificates(targetCert, targetKey, err);

            Database::Instance().SetConfig("https_cert_mode", "custom");
            Database::Instance().SetConfig("https_cert_source", "url");
            Database::Instance().SetConfig("https_cert_url", certUrl);
            Database::Instance().SetConfig("https_key_url", keyUrl);
            Database::Instance().SetConfig("https_cert_file", targetCert);
            Database::Instance().SetConfig("https_key_file", targetKey);
            return {
                {"success", true},
                {"cert_status", OpenSSLSession::GetCertStatusInfo()},
                {"cert_mode", "custom"}
            };
        } else {
            // Local path
            std::string certPath = params.value("cert_path", "");
            std::string keyPath = params.value("key_path", "");
            if (certPath.empty()) return { {"success", false}, {"error", "公钥证书路径不能为空"} };
            if (keyPath.empty()) return { {"success", false}, {"error", "私钥文件路径不能为空"} };

            if (!OpenSSLSession::ReloadCertificates(certPath, keyPath, err)) {
                return { {"success", false}, {"error", err} };
            }

            Database::Instance().SetConfig("https_cert_mode", "custom");
            Database::Instance().SetConfig("https_cert_source", "local");
            Database::Instance().SetConfig("https_cert_file", certPath);
            Database::Instance().SetConfig("https_key_file", keyPath);
            return {
                {"success", true},
                {"cert_status", OpenSSLSession::GetCertStatusInfo()},
                {"cert_mode", "custom"}
            };
        }
    } else if (action == "get_components") {
        std::string jsonStr = Utils::ExecCmd("sh /usr/share/proxyrelay/component_manager.sh status 2>/dev/null");
        if (jsonStr.empty()) {
            return { {"busy", false}, {"components", nlohmann::json::array()} };
        }
        try {
            return nlohmann::json::parse(jsonStr);
        } catch (...) {
            return { {"busy", false}, {"components", nlohmann::json::array()} };
        }
    } else if (action == "install_component") {
        std::string comp = params.value("name", "");
        std::string mirror = params.value("mirror", "ghfast");
        if (comp == "xray" || comp == "mihomo" || comp == "geoip" || comp == "geosite") {
            if (mirror != "official" && mirror != "ghfast") {
                mirror = "ghfast";
            }
            std::string cmd = "sh /usr/share/proxyrelay/component_manager.sh install " + comp + " " + mirror + " >/dev/null 2>&1 &";
            Utils::ExecCmd(cmd);
            return { {"success", true}, {"message", "组件下载与安装任务已在后台启动"} };
        }
        return { {"success", false}, {"error", "无效或不受支持的组件名称: " + comp} };
    } else if (action == "get_component_download_status") {
        bool running = (access("/var/run/proxyrelay_comp.lock", F_OK) == 0);
        std::string compName;
        std::ifstream lockFile("/var/run/proxyrelay_comp.lock");
        if (lockFile.is_open()) {
            std::getline(lockFile, compName);
        }
        std::string logContent;
        std::ifstream logFile("/var/log/proxyrelay/component_install.log");
        if (logFile.is_open()) {
            logFile.seekg(0, std::ios::end);
            size_t size = logFile.tellg();
            size_t offset = (size > 4096) ? size - 4096 : 0;
            logFile.seekg(offset, std::ios::beg);
            logContent.assign((std::istreambuf_iterator<char>(logFile)), std::istreambuf_iterator<char>());
        }
        return {
            {"running", running},
            {"component", compName},
            {"log", logContent}
        };
    } else if (action == "get_service_status") {
        return {
            {"installed", true},
            {"running", ProxyServer::Instance().IsRunning()}
        };
    } else if (action == "control_service") {
        std::string cmd = params.value("command", "restart");
        if (cmd == "start" || cmd == "stop" || cmd == "restart" || cmd == "reload") {
            Utils::ExecCmd("/etc/init.d/proxyrelay " + cmd + " >/dev/null 2>&1 &");
            return { {"success", true} };
        }
    } else if (action == "get_subscriptions") {
        auto subs = Database::Instance().GetAllSubscriptions();
        nlohmann::json arr = nlohmann::json::array();
        for (auto& s : subs) {
            if (s.resetCycleDays == 30 || s.resetCycleDays < 0) s.resetCycleDays = 0;
            if (s.resetStartDate.empty()) {
                s.resetStartDate = s.createdAt.empty() ? Utils::GetCurrentDate().substr(0, 10) : s.createdAt.substr(0, 10);
                Database::Instance().SaveSubscription(s);
            }
            auto cycleInfo = ClashManager::CalculateCycleInfo(s.resetStartDate, s.resetCycleDays, s.lastResetCycle, s.createdAt);
            auto ports = Database::Instance().GetPortsBySubscriptionId(s.id);

            arr.push_back({
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
        return arr;
    } else if (action == "import_clash_sub") {
        std::string url = Utils::Trim(params.value("url", ""));
        std::string name = Utils::Trim(params.value("name", ""));
        std::string group = Utils::Trim(params.value("group", ""));
        std::string includeFilter = Utils::Trim(params.value("includeFilter", ""));
        std::string excludeFilter = Utils::Trim(params.value("excludeFilter", ""));
        int resetCycleDays = params.value("resetCycleDays", 0);
        std::string resetStartDate = Utils::Trim(params.value("resetStartDate", ""));

        if (url.empty()) return { {"success", false}, {"error", "URL 或 YAML 节点文本不能为空"} };
        
        std::string yamlContent;
        ClashManager::SubscriptionUserInfo userInfo;
        bool isHttp = (url.rfind("http://", 0) == 0 || url.rfind("https://", 0) == 0);
        if (isHttp) {
            yamlContent = ClashManager::DownloadSubscription(url, &userInfo);
            if (yamlContent.empty()) {
                return { {"success", false}, {"error", "无法从订阅 URL 下载内容，请检查网络或订阅链接是否有效"} };
            }
        } else {
            yamlContent = url;
            ClashManager::ParseSubscriptionContentUserInfo(yamlContent, userInfo);
        }
        
        auto rawNodes = ClashManager::ParseSubscriptionNodes(yamlContent);
        if (rawNodes.empty()) {
            return { {"success", false}, {"error", "未从输入内容中解析到可用代理节点，请检查链接或 YAML 节点配置"} };
        }

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
        
        Database::Instance().SaveSubscription(sub);
        int subId = sub.id;
        if (subId <= 0) {
            auto allSubs = Database::Instance().GetAllSubscriptions();
            if (!allSubs.empty()) subId = allSubs.back().id;
        }
        
        int imported = 0;
        for (const auto& node : nodes) {
            ProxyPort p;
            p.upstreamType = "clash";
            p.description = (name.empty() ? "" : (name + " - ")) + node.name;
            p.upstreamHost = node.server;
            p.upstreamPort = node.port;
            p.clashNodeName = node.name;
            p.groupName = group.empty() ? "默认" : group;
            p.clashConfig = ClashManager::GenerateNodeConfig(node, 0);
            p.listenPort = 0;
            p.enabled = true;
            p.autoCheck = true;
            p.clashSubscriptionId = subId;
            if (Database::Instance().SaveProxyPort(p)) {
                imported++;
            }
        }
        Database::Instance().DeduplicateProxyPorts();
        ProxyServer::Instance().ReloadPorts();
        return { {"success", true}, {"importedCount", imported} };
    } else if (action == "save_subscription") {
        int id = params.value("id", 0);
        ClashSubscription sub;
        if (id > 0 && Database::Instance().GetSubscriptionById(id, sub)) {
            if (params.contains("name")) sub.name = Utils::Trim(params["name"].get<std::string>());
            if (params.contains("url")) sub.url = Utils::Trim(params["url"].get<std::string>());
            if (params.contains("updateIntervalDays")) sub.updateIntervalDays = params["updateIntervalDays"].get<int>();
            if (params.contains("websiteUrl")) sub.websiteUrl = Utils::Trim(params["websiteUrl"].get<std::string>());
            if (params.contains("includeFilter")) sub.includeFilter = Utils::Trim(params["includeFilter"].get<std::string>());
            if (params.contains("excludeFilter")) sub.excludeFilter = Utils::Trim(params["excludeFilter"].get<std::string>());
            if (params.contains("resetCycleDays")) {
                int d = params["resetCycleDays"].get<int>();
                sub.resetCycleDays = (d <= 0 || d == 30) ? 0 : d;
            }
            if (params.contains("resetStartDate")) {
                std::string d = Utils::Trim(params["resetStartDate"].get<std::string>());
                if (!d.empty()) sub.resetStartDate = d;
            }
            bool ok = Database::Instance().SaveSubscription(sub);
            if (ok) {
                if (sub.url.rfind("http://", 0) == 0 || sub.url.rfind("https://", 0) == 0) {
                    ClashManager::Instance().RefreshSubscription(id);
                } else if (!sub.rawContent.empty()) {
                    auto rawNodes = ClashManager::ParseSubscriptionNodes(sub.rawContent);
                    auto newNodes = ClashManager::FilterAndDeduplicateNodes(rawNodes, sub.includeFilter, sub.excludeFilter);
                    Database::Instance().DeletePortsBySubscriptionId(id);
                    for (const auto& node : newNodes) {
                        ProxyPort p;
                        p.upstreamType = "clash";
                        p.description = (sub.name.empty() ? "" : (sub.name + " - ")) + node.name;
                        p.upstreamHost = node.server;
                        p.upstreamPort = node.port;
                        p.clashNodeName = node.name;
                        p.groupName = "默认";
                        p.clashConfig = ClashManager::GenerateNodeConfig(node, 0);
                        p.listenPort = 0;
                        p.enabled = true;
                        p.autoCheck = true;
                        p.clashSubscriptionId = id;
                        Database::Instance().SaveProxyPort(p);
                    }
                    Database::Instance().DeduplicateProxyPorts();
                }
                ProxyServer::Instance().ReloadPorts();
            }
            return { {"success", ok} };
        }
        return { {"success", false}, {"error", "订阅不存在"} };
    } else if (action == "update_subscription") {
        int id = params.value("id", 0);
        int count = ClashManager::Instance().RefreshSubscription(id);
        if (count >= 0) {
            ProxyServer::Instance().ReloadPorts();
        }
        return { {"success", count >= 0}, {"updatedCount", (count >= 0 ? count : 0)} };
    } else if (action == "delete_subscription") {
        int id = params.value("id", 0);
        Database::Instance().DeletePortsBySubscriptionId(id);
        bool ok = Database::Instance().DeleteSubscription(id);
        if (ok) ProxyServer::Instance().ReloadPorts();
        return { {"success", ok} };
    } else if (action == "refresh_clash_node") {
        int portId = params.value("id", 0);
        if (portId <= 0) {
            auto subs = Database::Instance().GetAllSubscriptions();
            int totalUpdated = 0;
            for (const auto& s : subs) {
                int count = ClashManager::Instance().RefreshSubscription(s.id);
                if (count > 0) totalUpdated += count;
            }
            ProxyServer::Instance().ReloadPorts();
            return { {"success", true}, {"updatedCount", totalUpdated} };
        }
        ProxyPort port;
        if (Database::Instance().GetProxyPortById(portId, port)) {
            if (port.clashSubscriptionId > 0) {
                int count = ClashManager::Instance().RefreshSubscription(port.clashSubscriptionId);
                ProxyServer::Instance().ReloadPorts();
                return { {"success", true}, {"updatedCount", count} };
            }
        }
        return { {"success", true}, {"updatedCount", 0} };
    } else if (action == "export_config") {
        return Database::Instance().ExportConfig();
    } else if (action == "import_config") {
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
    } else if (action == "open_url") {
        return { {"success", true} };
    } else if (action == "exit_app") {
        Utils::ExecCmd("/etc/init.d/proxyrelay stop >/dev/null 2>&1 &");
        return { {"success", true} };
    } else if (action == "restart_service") {
        Utils::ExecCmd("/etc/init.d/proxyrelay restart >/dev/null 2>&1 &");
        return { {"success", true} };
    }

    return { {"success", true} };
}
