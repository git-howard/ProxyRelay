#include "ProxyServer.h"
#include "UserManager.h"
#include "TrafficMonitor.h"
#include "ConnectionLogger.h"
#include "RealtimeConnectionManager.h"
#include "Rules.h"
#include "ClashManager.h"
#include "UdpRelayManager.h"
#include "Utils.h"
#include <sstream>
#include <regex>
#include <poll.h>

static int SendToClient(SOCKET s, const char* buf, int len, std::shared_ptr<OpenSSLSession> tlsSession) {
    if (tlsSession) {
        return tlsSession->Write(buf, len);
    } else {
        int total = 0;
        while (total < len) {
            int sent = send(s, buf + total, len - total, 0);
            if (sent <= 0) return sent;
            total += sent;
        }
        return total;
    }
}

static int RecvFromClient(SOCKET s, char* buf, int len, std::shared_ptr<OpenSSLSession> tlsSession) {
    if (tlsSession) {
        return tlsSession->Read(buf, len);
    } else {
        return recv(s, buf, len, 0);
    }
}

static bool RecvExact(SOCKET s, char* buf, int len, std::shared_ptr<OpenSSLSession> tlsSession = nullptr) {
    int total = 0;
    while (total < len) {
        int r = RecvFromClient(s, buf + total, len - total, tlsSession);
        if (r <= 0) return false;
        total += r;
    }
    return true;
}

static bool CheckProxyTypeAllowed(const std::string& allowedConfig, const std::string& type) {
    if (allowedConfig == "none" || allowedConfig == "disabled" || allowedConfig == "off") return false;
    if (allowedConfig.empty() || allowedConfig == "all") return true;
    std::string s = "," + allowedConfig + ",";
    for (char& c : s) {
        if (c == '+' || c == ' ' || c == ';' || c == '/') c = ',';
        else c = (char)::tolower((unsigned char)c);
    }
    std::string target = "," + type + ",";
    return s.find(target) != std::string::npos;
}

static bool ReadHttpRequestHeaders(SOCKET s, std::shared_ptr<OpenSSLSession> tlsSession,
                                   std::string& req, std::string& extraPayload) {
    req.clear();
    extraPayload.clear();
    char buf[4096];
    while (req.size() < 65536) {
        int r = 0;
        if (tlsSession) {
            r = tlsSession->Read(buf, sizeof(buf));
        } else {
            r = recv(s, buf, sizeof(buf), 0);
        }
        if (r <= 0) break;
        req.append(buf, r);
        size_t pos = req.find("\r\n\r\n");
        if (pos != std::string::npos) {
            extraPayload = req.substr(pos + 4);
            req = req.substr(0, pos + 4);
            return true;
        }
        pos = req.find("\n\n");
        if (pos != std::string::npos) {
            extraPayload = req.substr(pos + 2);
            req = req.substr(0, pos + 2);
            return true;
        }
    }
    return !req.empty();
}

ProxyServer& ProxyServer::Instance() {
    static ProxyServer instance;
    return instance;
}

ProxyServer::~ProxyServer() {
    Stop();
}

bool ProxyServer::Start() {
    if (running_.load()) return true;
    running_.store(true);
    startTime_.store((int64_t)time(nullptr));

    ReloadPorts();
    return true;
}

void ProxyServer::Stop() {
    if (!running_.load()) return;
    running_.store(false);
    startTime_.store(0);

    std::vector<std::thread> threadsToJoin;
    std::thread autoThreadToJoin;

    {
        std::lock_guard<std::mutex> lock(portsMutex_);
        for (auto& kv : listenSockets_) {
            if (kv.second != INVALID_SOCKET) {
                shutdown(kv.second, SHUT_RDWR);
                closesocket(kv.second);
            }
        }
        listenSockets_.clear();

        for (auto& kv : listenerThreads_) {
            if (kv.second.joinable()) {
                threadsToJoin.push_back(std::move(kv.second));
            }
        }
        listenerThreads_.clear();

        if (autoProxySocket_.load() != INVALID_SOCKET) {
            SOCKET s = autoProxySocket_.exchange(INVALID_SOCKET);
            shutdown(s, SHUT_RDWR);
            closesocket(s);
        }
        if (autoProxyThread_.joinable()) {
            autoThreadToJoin = std::move(autoProxyThread_);
        }
        currentAutoPort_ = 0;
    }

    // 在锁外等待线程退出，杜绝死锁
    for (auto& t : threadsToJoin) {
        if (t.joinable()) t.join();
    }
    if (autoThreadToJoin.joinable()) {
        autoThreadToJoin.join();
    }

    ClashManager::Instance().StopAll();
}

void ProxyServer::ReloadPorts() {
    std::vector<std::thread> oldThreads;
    std::thread oldAutoThread;

    std::string autoPortStr = Database::Instance().GetConfig("auto_proxy_port", "1080");
    int autoPort = std::atoi(autoPortStr.c_str());
    bool needRestartAuto = (autoPort != currentAutoPort_ || autoProxySocket_.load() == INVALID_SOCKET);

    {
        std::lock_guard<std::mutex> lock(portsMutex_);
        // 关闭现有各节点独立监听 (保留全局自动代理端口)
        for (auto it = listenSockets_.begin(); it != listenSockets_.end(); ) {
            if (autoProxySocket_.load() != INVALID_SOCKET && it->second == autoProxySocket_.load()) {
                ++it;
                continue;
            }
            if (it->second != INVALID_SOCKET) {
                shutdown(it->second, SHUT_RDWR);
                closesocket(it->second);
            }
            it = listenSockets_.erase(it);
        }

        for (auto& kv : listenerThreads_) {
            if (kv.second.joinable()) {
                oldThreads.push_back(std::move(kv.second));
            }
        }
        listenerThreads_.clear();

        if (needRestartAuto) {
            if (autoProxySocket_.load() != INVALID_SOCKET) {
                SOCKET s = autoProxySocket_.exchange(INVALID_SOCKET);
                shutdown(s, SHUT_RDWR);
                closesocket(s);
                listenSockets_.erase(currentAutoPort_);
            }
            if (autoProxyThread_.joinable()) {
                oldAutoThread = std::move(autoProxyThread_);
            }
        }
    }

    // 在锁外等待旧线程退出，杜绝死锁
    for (auto& t : oldThreads) {
        if (t.joinable()) t.join();
    }
    if (oldAutoThread.joinable()) {
        oldAutoThread.join();
    }

    auto ports = Database::Instance().GetAllProxyPorts();

    {
        std::lock_guard<std::mutex> lock(portsMutex_);
        for (const auto& p : ports) {
            if (p.enabled && p.listenPort > 0) {
                listenerThreads_[p.id] = std::thread(&ProxyServer::ListenerThread, this, p);
            }
        }

        if (needRestartAuto) {
            currentAutoPort_ = autoPort;
            if (autoPort > 0) {
                ProxyPort ap;
                ap.id = -100;
                ap.listenPort = autoPort;
                ap.description = "全局智能分流端口";
                ap.upstreamType = "auto";
                autoProxyThread_ = std::thread(&ProxyServer::ListenerThread, this, ap);
            }
        }
    }
}

std::vector<int> ProxyServer::GetListeningPorts() const {
    std::lock_guard<std::mutex> lock(portsMutex_);
    std::vector<int> list;
    for (const auto& kv : listenSockets_) {
        list.push_back(kv.first);
    }
    return list;
}

void ProxyServer::ListenerThread(ProxyPort port) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) {
        std::cerr << "[ProxyServer] Error: socket() failed for port " << port.listenPort
                  << ": " << strerror(errno) << std::endl;
        if (port.id == -100) currentAutoPort_ = 0;
        return;
    }

    int opt = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef SO_REUSEPORT
    setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
#endif

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port.listenPort);

    if (bind(s, (sockaddr*)&addr, sizeof(addr)) != 0) {
        std::cerr << "[ProxyServer] Error: bind() failed on 0.0.0.0:" << port.listenPort
                  << " (" << port.description << "): " << strerror(errno) << std::endl;
        closesocket(s);
        if (port.id == -100) currentAutoPort_ = 0;
        return;
    }

    if (listen(s, 128) != 0) {
        std::cerr << "[ProxyServer] Error: listen() failed on 0.0.0.0:" << port.listenPort
                  << " (" << port.description << "): " << strerror(errno) << std::endl;
        closesocket(s);
        if (port.id == -100) currentAutoPort_ = 0;
        return;
    }

    std::cout << "[ProxyServer] Successfully listening on 0.0.0.0:" << port.listenPort
              << " (" << port.description << ")" << std::endl;

    {
        std::lock_guard<std::mutex> lock(portsMutex_);
        listenSockets_[port.listenPort] = s;
        if (port.id == -100) {
            autoProxySocket_.store(s);
        }
    }

    while (running_.load()) {
        sockaddr_in clientAddr{};
        socklen_t clientLen = sizeof(clientAddr);
        SOCKET clientSocket = accept(s, (sockaddr*)&clientAddr, &clientLen);
        if (clientSocket == INVALID_SOCKET) {
            if (!running_.load() || errno == EBADF || errno == EINVAL) break;
            continue;
        }

        char ipStr[INET_ADDRSTRLEN] = {};
        inet_ntop(AF_INET, &clientAddr.sin_addr, ipStr, sizeof(ipStr));
        std::string clientIP = ipStr;

        std::thread(&ProxyServer::HandleClient, this, clientSocket, clientIP, port).detach();
    }

    closesocket(s);
    {
        std::lock_guard<std::mutex> lock(portsMutex_);
        listenSockets_.erase(port.listenPort);
        if (port.id == -100 && autoProxySocket_.load() == s) {
            autoProxySocket_.store(INVALID_SOCKET);
        }
    }
}

void ProxyServer::HandleClient(SOCKET clientSocket, const std::string& clientAddr, ProxyPort port) {
    // 设置超时与优化选项
    struct timeval tv{30, 0};
    setsockopt(clientSocket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(clientSocket, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    int nodelay = 1;
    setsockopt(clientSocket, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));

    char peekBuf[16] = {};
    int peeked = recv(clientSocket, peekBuf, sizeof(peekBuf), MSG_PEEK);
    if (peeked <= 0) {
        closesocket(clientSocket);
        return;
    }

    std::string allowedType = Database::Instance().GetConfig("inbound_proxy_type", "all");

    // 1. SOCKS5 探测 (0x05)
    if ((unsigned char)peekBuf[0] == 0x05) {
        if (!CheckProxyTypeAllowed(allowedType, "socks5")) {
            closesocket(clientSocket);
            return;
        }
        HandleSocks5Proxy(clientSocket, clientAddr, port, 0, "", "", nullptr);
        return;
    }

    // 2. HTTPS / TLS 探测 (0x16)
    if ((unsigned char)peekBuf[0] == 0x16) {
        if (!CheckProxyTypeAllowed(allowedType, "https")) {
            closesocket(clientSocket);
            return;
        }
        auto tlsSession = std::make_shared<OpenSSLSession>();
        if (!tlsSession->AcceptHandshake(clientSocket)) {
            std::cerr << "[ProxyServer] TLS handshake failed from " << clientAddr << std::endl;
            closesocket(clientSocket);
            return;
        }

        char tlsPeek[4] = {};
        int pr = tlsSession->Peek(tlsPeek, sizeof(tlsPeek));
        if (pr > 0 && (unsigned char)tlsPeek[0] == 0x05) {
            HandleSocks5Proxy(clientSocket, clientAddr, port, 0, "", "", tlsSession);
            return;
        }

        std::string request, extraPayload;
        if (!ReadHttpRequestHeaders(clientSocket, tlsSession, request, extraPayload)) {
            closesocket(clientSocket);
            return;
        }
        HandleHttpProxy(clientSocket, clientAddr, port, 0, "", request, extraPayload, tlsSession);
        return;
    }

    // 3. 普通明文 HTTP / CONNECT
    if (!CheckProxyTypeAllowed(allowedType, "http")) {
        closesocket(clientSocket);
        return;
    }
    std::string request, extraPayload;
    if (!ReadHttpRequestHeaders(clientSocket, nullptr, request, extraPayload)) {
        closesocket(clientSocket);
        return;
    }
    HandleHttpProxy(clientSocket, clientAddr, port, 0, "", request, extraPayload, nullptr);
}

void ProxyServer::HandleHttpProxy(SOCKET clientSocket, const std::string& clientAddr,
                                 const ProxyPort& port, int userId, const std::string& username,
                                 const std::string& req, const std::string& extraPayload,
                                 std::shared_ptr<OpenSSLSession> tlsSession) {
    std::string clientIP = Utils::GetClientIP(clientAddr);
    std::istringstream stream(req);
    std::string method, url, version;
    stream >> method >> url >> version;
    std::string inboundType = (tlsSession != nullptr || method == "CONNECT") ? "HTTPS" : "HTTP";

    std::string targetHost;
    int targetPort = 80;

    if (method == "CONNECT") {
        targetPort = 443;
        size_t colon = url.find(':');
        if (colon != std::string::npos) {
            targetHost = url.substr(0, colon);
            targetPort = std::atoi(url.substr(colon + 1).c_str());
        } else {
            targetHost = url;
        }
    } else {
        // HTTP GET/POST: http://domain:port/path
        size_t httpPos = url.find("http://");
        if (httpPos != std::string::npos) {
            std::string hostPart = url.substr(httpPos + 7);
            size_t slash = hostPart.find('/');
            if (slash != std::string::npos) hostPart = hostPart.substr(0, slash);
            size_t colon = hostPart.find(':');
            if (colon != std::string::npos) {
                targetHost = hostPart.substr(0, colon);
                targetPort = std::atoi(hostPart.substr(colon + 1).c_str());
            } else {
                targetHost = hostPart;
                targetPort = 80;
            }
        } else if (!url.empty() && url[0] == '/') {
            // 相对路径 URL: 从 Host: 头提取
            size_t hostPos = req.find("\r\nHost: ");
            if (hostPos == std::string::npos) hostPos = req.find("\nHost: ");
            if (hostPos != std::string::npos) {
                size_t valStart = req.find(':', hostPos) + 1;
                while (valStart < req.size() && (req[valStart] == ' ' || req[valStart] == '\t')) valStart++;
                size_t endHost = req.find("\r\n", valStart);
                if (endHost == std::string::npos) endHost = req.find('\n', valStart);
                std::string hostVal = req.substr(valStart, endHost - valStart);
                while (!hostVal.empty() && (hostVal.back() == ' ' || hostVal.back() == '\r')) hostVal.pop_back();
                size_t colon = hostVal.rfind(':');
                if (colon != std::string::npos) {
                    targetHost = hostVal.substr(0, colon);
                    targetPort = std::atoi(hostVal.substr(colon + 1).c_str());
                } else {
                    targetHost = hostVal;
                    targetPort = (tlsSession != nullptr ? 443 : 80);
                }
            }
        }
    }

    if (targetHost.empty()) {
        const char* err400 = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
        SendToClient(clientSocket, err400, strlen(err400), tlsSession);
        closesocket(clientSocket);
        return;
    }

    // 认证处理
    int currentUserId = userId;
    std::string authUser = username;
    UserInfo user;
    bool authenticated = false;

    // 检查客户端是否携带了 Proxy-Authorization 或 Authorization 头
    std::string authVal = "";
    std::string lowerReq = req;
    for (char& c : lowerReq) c = (char)::tolower((unsigned char)c);
    
    size_t authPos = lowerReq.find("proxy-authorization:");
    if (authPos != std::string::npos) {
        size_t lineEnd = req.find("\r\n", authPos);
        if (lineEnd == std::string::npos) lineEnd = req.find('\n', authPos);
        size_t valStart = authPos + 20;
        while (valStart < lineEnd && (req[valStart] == ' ' || req[valStart] == '\t')) valStart++;
        authVal = Utils::Trim(req.substr(valStart, lineEnd - valStart));
    } else {
        authPos = lowerReq.find("authorization:");
        if (authPos != std::string::npos) {
            size_t lineEnd = req.find("\r\n", authPos);
            if (lineEnd == std::string::npos) lineEnd = req.find('\n', authPos);
            size_t valStart = authPos + 14;
            while (valStart < lineEnd && (req[valStart] == ' ' || req[valStart] == '\t')) valStart++;
            authVal = Utils::Trim(req.substr(valStart, lineEnd - valStart));
        }
    }

    if (!authVal.empty()) {
        std::string u, p;
        if (Utils::ParseBasicAuth(authVal, u, p)) {
            // 规则 3：提供了用户名密码，按优先级与密码、IP 严格比对
            if (UserManager::Instance().Authenticate(u, p, clientIP, user)) {
                currentUserId = user.id;
                authUser = user.username;
                authenticated = true;
            }
        }
    } else {
        // 规则 2：未提供凭据时，探测是否满足无密码且有IP范围的免认证登录策略
        if (UserManager::Instance().Authenticate("", "", clientIP, user)) {
            currentUserId = user.id;
            authUser = user.username;
            authenticated = true;
        }
    }

    if (!authenticated) {
        const char* err407 = "HTTP/1.1 407 Proxy Authentication Required\r\n"
                             "Proxy-Authenticate: Basic realm=\"ProxyRelay\"\r\n"
                             "Content-Length: 0\r\n\r\n";
        SendToClient(clientSocket, err407, strlen(err407), tlsSession);
        closesocket(clientSocket);
        return;
    }

    // 分流规则匹配
    std::string targetIP = "";
    std::string targetDomain = "";
    struct in_addr addrTmp;
    if (inet_pton(AF_INET, targetHost.c_str(), &addrTmp) == 1) {
        targetIP = targetHost;
    } else {
        targetDomain = targetHost;
    }
    std::string matchedGroup;
    bool isFallback = false;
    int proxyId = RuleManager::Instance().GetMatchingProxyId(targetIP, targetDomain, &matchedGroup, &isFallback);
    if (proxyId == -2) { // 阻断
        ConnectionLogger::Instance().Log(authUser, clientAddr, targetHost, targetPort, "REJECT", "规则拦截阻断", inboundType);
        const char* err403 = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
        SendToClient(clientSocket, err403, strlen(err403), tlsSession);
        closesocket(clientSocket);
        return;
    }

    auto connRes = ConnectWithFallback(proxyId, targetHost, targetPort, matchedGroup, isFallback);
    if (connRes.socket == INVALID_SOCKET) {
        ConnectionLogger::Instance().Log(authUser, clientAddr, targetHost, targetPort, "FAILED", "上游连接失败", inboundType);
        const char* err502 = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
        SendToClient(clientSocket, err502, strlen(err502), tlsSession);
        closesocket(clientSocket);
        return;
    }

    if (method == "CONNECT") {
        const char* established = "HTTP/1.1 200 Connection Established\r\n\r\n";
        SendToClient(clientSocket, established, strlen(established), tlsSession);
        if (!extraPayload.empty()) {
            send(connRes.socket, extraPayload.data(), extraPayload.size(), 0);
        }
    } else {
        // 普通 HTTP 请求首包转发至上游（相对路径重写 + 过滤代理头）
        std::string path = "/";
        size_t httpPos = url.find("http://");
        if (httpPos != std::string::npos) {
            size_t slash = url.find('/', httpPos + 7);
            if (slash != std::string::npos) path = url.substr(slash);
        } else if (!url.empty() && url[0] == '/') {
            path = url;
        }

        std::string modifiedReq = method + " " + path + " " + version + "\r\n";
        std::istringstream hStream(req);
        std::string hLine;
        bool firstLine = true;
        while (std::getline(hStream, hLine)) {
            if (firstLine) { firstLine = false; continue; }
            std::string lowerH = Utils::ToLower(hLine);
            if (lowerH.find("proxy-authorization:") == 0) continue;
            if (lowerH.find("proxy-connection:") == 0) {
                modifiedReq += "Connection: keep-alive\r\n";
                continue;
            }
            modifiedReq += hLine + "\n";
        }
        if (!extraPayload.empty()) {
            modifiedReq += extraPayload;
        }
        send(connRes.socket, modifiedReq.c_str(), modifiedReq.length(), 0);
    }

    uint64_t connId = RealtimeConnectionManager::Instance().AddConnection(
        authUser, clientAddr, targetHost, targetPort, connRes.description, clientSocket, connRes.socket, inboundType);
    ConnectionLogger::Instance().Log(authUser, clientAddr, targetHost, targetPort, method, connRes.description, inboundType);

    RelayData(clientSocket, connRes.socket, currentUserId, connRes.portId, connId, tlsSession);
}

void ProxyServer::HandleSocks5Proxy(SOCKET clientSocket, const std::string& clientAddr,
                                   const ProxyPort& port, int userId, const std::string& username,
                                   const std::string& initialData,
                                   std::shared_ptr<OpenSSLSession> tlsSession) {
    std::string clientIP = Utils::GetClientIP(clientAddr);

    // 1. 协商认证方式
    unsigned char greeting[2] = {};
    if (!initialData.empty()) {
        greeting[0] = (unsigned char)initialData[0];
        greeting[1] = (initialData.size() > 1) ? (unsigned char)initialData[1] : 0;
    } else {
        if (!RecvExact(clientSocket, (char*)greeting, 2, tlsSession)) {
            closesocket(clientSocket);
            return;
        }
    }

    if (greeting[0] != 0x05 || greeting[1] == 0) {
        closesocket(clientSocket);
        return;
    }
    int numMethods = greeting[1];
    std::vector<unsigned char> methods(numMethods);
    if (initialData.size() >= (size_t)(2 + numMethods)) {
        memcpy(methods.data(), initialData.data() + 2, numMethods);
    } else {
        if (!RecvExact(clientSocket, (char*)methods.data(), numMethods, tlsSession)) {
            closesocket(clientSocket);
            return;
        }
    }

    bool supportsNoAuth = false;
    bool supportsUserPass = false;
    for (int i = 0; i < numMethods; ++i) {
        if (methods[i] == 0x00) supportsNoAuth = true;
        if (methods[i] == 0x02) supportsUserPass = true;
    }

    int currentUserId = userId;
    std::string authUsername = username;
    UserInfo user;

    // 优先根据用户优先级检查当前 IP 是否匹配免认证策略 (且客户端协商方法支持 0x00 免密)
    if (supportsNoAuth && UserManager::Instance().AuthenticateByIP(clientIP, user)) {
        currentUserId = user.id;
        authUsername = user.username;
        unsigned char authResp[2] = {0x05, 0x00};
        SendToClient(clientSocket, (char*)authResp, 2, tlsSession);
    } else if (supportsUserPass) {
        // 客户端支持账号密码认证，选择 0x02 要求客户端提供用户名/密码 (RFC 1929)
        unsigned char authReq[2] = {0x05, 0x02};
        SendToClient(clientSocket, (char*)authReq, 2, tlsSession);

        unsigned char authHdr[2] = {};
        if (!RecvExact(clientSocket, (char*)authHdr, 2, tlsSession) || authHdr[0] != 0x01) {
            closesocket(clientSocket);
            return;
        }
        int ulen = authHdr[1];
        std::string reqUser(ulen, '\0');
        if (ulen > 0) {
            if (!RecvExact(clientSocket, &reqUser[0], ulen, tlsSession)) {
                closesocket(clientSocket);
                return;
            }
        }
        unsigned char plenBuf[1] = {};
        if (!RecvExact(clientSocket, (char*)plenBuf, 1, tlsSession)) {
            closesocket(clientSocket);
            return;
        }
        int plen = plenBuf[0];
        std::string reqPass(plen, '\0');
        if (plen > 0) {
            if (!RecvExact(clientSocket, &reqPass[0], plen, tlsSession)) {
                closesocket(clientSocket);
                return;
            }
        }

        if (!UserManager::Instance().Authenticate(reqUser, reqPass, clientIP, user)) {
            unsigned char failResp[2] = {0x01, 0x01};
            SendToClient(clientSocket, (char*)failResp, 2, tlsSession);
            closesocket(clientSocket);
            return;
        }

        unsigned char okResp[2] = {0x01, 0x00};
        SendToClient(clientSocket, (char*)okResp, 2, tlsSession);
        currentUserId = user.id;
        authUsername = user.username;
    } else {
        unsigned char noAcceptable[2] = {0x05, 0xFF};
        SendToClient(clientSocket, (char*)noAcceptable, 2, tlsSession);
        closesocket(clientSocket);
        return;
    }

    // 2. 接收连接请求命令 (RFC 1928)
    char cmdBuf[4] = {};
    if (!RecvExact(clientSocket, cmdBuf, 4, tlsSession)) {
        closesocket(clientSocket);
        return;
    }
    int cmd = (unsigned char)cmdBuf[1];
    if ((unsigned char)cmdBuf[0] != 0x05 || (cmd != 0x01 && cmd != 0x03)) { // 支持 CONNECT(0x01) 与 UDP ASSOCIATE(0x03)
        char fail[10] = {0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
        SendToClient(clientSocket, fail, 10, tlsSession);
        closesocket(clientSocket);
        return;
    }

    if (cmd == 0x03) { // UDP ASSOCIATE
        UdpRelayManager::Instance().HandleSocks5UdpAssociate(clientSocket, clientIP, port, currentUserId, authUsername, cmdBuf, tlsSession);
        return;
    }

    std::string targetHost;
    int targetPort = 0;
    int addrType = cmdBuf[3];

    if (addrType == 0x01) { // IPv4
        char ipAndPort[6] = {};
        if (!RecvExact(clientSocket, ipAndPort, 6, tlsSession)) { closesocket(clientSocket); return; }
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, ipAndPort, ip, sizeof(ip));
        targetHost = ip;
        targetPort = ntohs(*(uint16_t*)&ipAndPort[4]);
    } else if (addrType == 0x03) { // 域名
        unsigned char domainLen = 0;
        if (!RecvExact(clientSocket, (char*)&domainLen, 1, tlsSession) || domainLen == 0) { closesocket(clientSocket); return; }
        std::string dom(domainLen, '\0');
        if (!RecvExact(clientSocket, &dom[0], domainLen, tlsSession)) { closesocket(clientSocket); return; }
        uint16_t netPort = 0;
        if (!RecvExact(clientSocket, (char*)&netPort, 2, tlsSession)) { closesocket(clientSocket); return; }
        targetHost = dom;
        targetPort = ntohs(netPort);
    } else {
        char fail[10] = {0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
        SendToClient(clientSocket, fail, 10, tlsSession);
        closesocket(clientSocket);
        return;
    }

    std::string targetIP = "";
    std::string targetDomain = "";
    struct in_addr addrTmp;
    if (inet_pton(AF_INET, targetHost.c_str(), &addrTmp) == 1) {
        targetIP = targetHost;
    } else {
        targetDomain = targetHost;
    }

    std::string matchedGroup;
    bool isFallback = false;
    int proxyId = RuleManager::Instance().GetMatchingProxyId(targetIP, targetDomain, &matchedGroup, &isFallback);
    if (proxyId == -2) {
        char failResp[10] = {0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
        SendToClient(clientSocket, failResp, 10, tlsSession);
        closesocket(clientSocket);
        return;
    }

    auto connRes = ConnectWithFallback(proxyId, targetHost, targetPort, matchedGroup, isFallback);
    if (connRes.socket == INVALID_SOCKET) {
        char failResp[10] = {0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0}; // Connection refused
        SendToClient(clientSocket, failResp, 10, tlsSession);
        closesocket(clientSocket);
        return;
    }

    char successResp[10] = {0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
    SendToClient(clientSocket, successResp, 10, tlsSession);

    std::string inboundType = (tlsSession != nullptr) ? "SOCKS5-TLS" : "SOCKS5";
    uint64_t connId = RealtimeConnectionManager::Instance().AddConnection(
        authUsername, clientAddr, targetHost, targetPort, connRes.description, clientSocket, connRes.socket, inboundType);
    ConnectionLogger::Instance().Log(authUsername, clientAddr, targetHost, targetPort, "SOCKS5", connRes.description, inboundType);

    RelayData(clientSocket, connRes.socket, currentUserId, connRes.portId, connId, tlsSession);
}

ProxyServer::ProxyConnResult ProxyServer::ConnectWithFallback(int preferredProxyId, const std::string& targetHost,
                                                           int targetPort, const std::string& targetGroup,
                                                           bool isFallback) {
    ProxyConnResult res;

    // 0: 直连
    if (preferredProxyId == 0) {
        res.socket = ConnectDirect(targetHost, targetPort);
        res.portId = 0;
        res.description = isFallback ? "DIRECT 兜底直连" : "DIRECT 直连";
        return res;
    }

    // -2: 阻断
    if (preferredProxyId == -2) {
        res.socket = INVALID_SOCKET;
        res.portId = 0;
        res.description = isFallback ? "REJECT 兜底阻断" : "REJECT 阻断";
        return res;
    }

    // 1. 指定了具体代理节点 ID
    if (preferredProxyId > 0) {
        ProxyPort p;
        if (Database::Instance().GetProxyPortById(preferredProxyId, p) && p.enabled) {
            res.socket = ConnectToUpstream(p, targetHost, targetPort);
            if (res.socket != INVALID_SOCKET) {
                res.portId = p.id;
                res.description = (isFallback ? "[兜底] " : "") + (p.description.empty() ? p.upstreamHost : p.description);
                return res;
            }
            // 指定节点单点连接失败时，若其有所属具体分组（非"默认"），尝试同组其他节点
            if (!p.groupName.empty() && p.groupName != "默认") {
                auto ports = Database::Instance().GetAllProxyPorts();
                for (const auto& alt : ports) {
                    if (alt.enabled && alt.id != p.id && alt.groupName == p.groupName) {
                        res.socket = ConnectToUpstream(alt, targetHost, targetPort);
                        if (res.socket != INVALID_SOCKET) {
                            res.portId = alt.id;
                            res.description = (isFallback ? "[兜底:" : "[") + alt.groupName + "] " + (alt.description.empty() ? alt.upstreamHost : alt.description);
                            return res;
                        }
                    }
                }
            }
        }
    }

    // 2. 按分组轮询尝试
    if (!targetGroup.empty() || preferredProxyId == -3) {
        auto ports = Database::Instance().GetAllProxyPorts();
        for (const auto& p : ports) {
            if (p.enabled && (targetGroup.empty() || p.groupName == targetGroup)) {
                res.socket = ConnectToUpstream(p, targetHost, targetPort);
                if (res.socket != INVALID_SOCKET) {
                    res.portId = p.id;
                    res.description = (isFallback ? "[兜底:" : "[") + p.groupName + "] " + (p.description.empty() ? p.upstreamHost : p.description);
                    return res;
                }
            }
        }
    }

    // 3. 严格规则控制：如果命中明确策略规则（非兜底规则，!isFallback），严格执行分流策略！
    // 绝不跨国越权串流到兜底规则（如从英国策略串到日本兜底），避免业务风控与安全问题
    if (!isFallback) {
        res.socket = INVALID_SOCKET;
        res.portId = 0;
        res.description = "策略代理节点连接失败";
        return res;
    }

    // 4. 若为兜底规则（isFallback == true），尝试兜底数据库配置规则
    RoutingRule fallbackRule;
    if (Database::Instance().GetFallbackRule(fallbackRule)) {
        bool alreadyTried = (preferredProxyId == fallbackRule.proxyId && targetGroup == fallbackRule.targetGroup);
        if (!alreadyTried) {
            if (fallbackRule.proxyId == 0) {
                res.socket = ConnectDirect(targetHost, targetPort);
                res.portId = 0;
                res.description = "DIRECT 兜底直连";
                return res;
            } else if (fallbackRule.proxyId == -2) {
                res.socket = INVALID_SOCKET;
                res.description = "REJECT 兜底阻断";
                return res;
            } else if (!fallbackRule.targetGroup.empty() || fallbackRule.proxyId == -3) {
                auto ports = Database::Instance().GetAllProxyPorts();
                for (const auto& p : ports) {
                    if (p.enabled && (fallbackRule.targetGroup.empty() || p.groupName == fallbackRule.targetGroup)) {
                        res.socket = ConnectToUpstream(p, targetHost, targetPort);
                        if (res.socket != INVALID_SOCKET) {
                            res.portId = p.id;
                            res.description = "[兜底:" + p.groupName + "] " + (p.description.empty() ? p.upstreamHost : p.description);
                            return res;
                        }
                    }
                }
            } else if (fallbackRule.proxyId > 0) {
                ProxyPort p;
                if (Database::Instance().GetProxyPortById(fallbackRule.proxyId, p) && p.enabled) {
                    res.socket = ConnectToUpstream(p, targetHost, targetPort);
                    if (res.socket != INVALID_SOCKET) {
                        res.portId = p.id;
                        res.description = "[兜底] " + (p.description.empty() ? p.upstreamHost : p.description);
                        return res;
                    }
                }
            }
        }
    }

    // 5. 最终失败
    res.socket = INVALID_SOCKET;
    res.portId = 0;
    res.description = "上游节点连接失败";
    return res;
}

SOCKET ProxyServer::ConnectDirect(const std::string& targetHost, int targetPort) {
    struct addrinfo hints{}, *result = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    std::string portStr = std::to_string(targetPort);
    if (getaddrinfo(targetHost.c_str(), portStr.c_str(), &hints, &result) != 0 || !result) {
        return INVALID_SOCKET;
    }

    SOCKET s = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (s == INVALID_SOCKET) {
        freeaddrinfo(result);
        return INVALID_SOCKET;
    }

    // 5秒超时
    timeval tv{5, 0};
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (connect(s, result->ai_addr, result->ai_addrlen) != 0) {
        closesocket(s);
        freeaddrinfo(result);
        return INVALID_SOCKET;
    }

    freeaddrinfo(result);
    return s;
}

SOCKET ProxyServer::ConnectToUpstream(const ProxyPort& port, const std::string& targetHost, int targetPort) {
    if (port.upstreamType == "socks5") {
        return ConnectToSocks5(port, targetHost, targetPort);
    } else if (port.upstreamType == "http") {
        return ConnectToHttpProxy(port, targetHost, targetPort);
    } else if (port.upstreamType == "clash") {
        return ConnectToClash(port, targetHost, targetPort);
    } else {
        return ConnectDirect(targetHost, targetPort);
    }
}

SOCKET ProxyServer::ConnectToClash(const ProxyPort& port, const std::string& targetHost, int targetPort) {
    int localSocksPort = ClashManager::Instance().GetLocalSocksPort(port.id);
    if (localSocksPort <= 0 && !port.clashConfig.empty()) {
        localSocksPort = ClashManager::Instance().StartClash(port.id, port.clashConfig);
    }
    if (localSocksPort <= 0) {
        return INVALID_SOCKET;
    }
    ProxyPort localProxy;
    localProxy.upstreamHost = "127.0.0.1";
    localProxy.upstreamPort = localSocksPort;
    SOCKET s = ConnectToSocks5(localProxy, targetHost, targetPort);
    if (s == INVALID_SOCKET && !port.clashConfig.empty()) {
        std::cerr << "[ProxyServer] ConnectToClash failed for port " << port.id 
                  << " (localPort=" << localSocksPort << "), restarting core and retrying..." << std::endl;
        ClashManager::Instance().StopClash(port.id);
        localSocksPort = ClashManager::Instance().StartClash(port.id, port.clashConfig);
        if (localSocksPort > 0) {
            localProxy.upstreamPort = localSocksPort;
            s = ConnectToSocks5(localProxy, targetHost, targetPort);
        }
    }
    return s;
}

SOCKET ProxyServer::ConnectToSocks5(const ProxyPort& port, const std::string& targetHost, int targetPort) {
    SOCKET s = ConnectDirect(port.upstreamHost, port.upstreamPort);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;

    // 1. SOCKS5 握手认证协商
    bool hasAuth = !port.upstreamUser.empty();
    if (hasAuth) {
        char req[4] = {0x05, 0x02, 0x00, 0x02}; // 支持 NO_AUTH(0x00) 与 USER_PASS(0x02)
        if (send(s, req, 4, 0) != 4) { closesocket(s); return INVALID_SOCKET; }
    } else {
        char req[3] = {0x05, 0x01, 0x00};
        if (send(s, req, 3, 0) != 3) { closesocket(s); return INVALID_SOCKET; }
    }

    char resp[2] = {};
    if (!RecvExact(s, resp, 2, nullptr) || (unsigned char)resp[0] != 0x05) {
        closesocket(s);
        return INVALID_SOCKET;
    }

    if (resp[1] == 0x02) {
        // RFC 1929 用户名密码认证
        std::string authPkt;
        authPkt.push_back(0x01); // 认证版本
        authPkt.push_back((char)std::min((size_t)255, port.upstreamUser.length()));
        authPkt.append(port.upstreamUser.substr(0, 255));
        authPkt.push_back((char)std::min((size_t)255, port.upstreamPass.length()));
        authPkt.append(port.upstreamPass.substr(0, 255));

        if (send(s, authPkt.data(), authPkt.size(), 0) != (int)authPkt.size()) {
            closesocket(s);
            return INVALID_SOCKET;
        }

        char authResp[2] = {};
        if (!RecvExact(s, authResp, 2, nullptr) || authResp[1] != 0x00) {
            closesocket(s);
            return INVALID_SOCKET;
        }
    } else if (resp[1] != 0x00) {
        closesocket(s);
        return INVALID_SOCKET;
    }

    // 2. CONNECT 请求 (自适应 IPv4, IPv6, 域名)
    std::string cmd;
    cmd.push_back(0x05); // VER
    cmd.push_back(0x01); // CMD: CONNECT
    cmd.push_back(0x00); // RSV

    in_addr addr4{};
    in6_addr addr6{};
    if (inet_pton(AF_INET, targetHost.c_str(), &addr4) == 1) {
        cmd.push_back(0x01); // IPv4
        cmd.append((const char*)&addr4.s_addr, 4);
    } else if (inet_pton(AF_INET6, targetHost.c_str(), &addr6) == 1) {
        cmd.push_back(0x04); // IPv6
        cmd.append((const char*)&addr6.s6_addr, 16);
    } else {
        cmd.push_back(0x03); // 域名
        cmd.push_back((char)targetHost.length());
        cmd.append(targetHost);
    }
    uint16_t netPort = htons(targetPort);
    cmd.append((const char*)&netPort, 2);

    if (send(s, cmd.data(), cmd.size(), 0) != (int)cmd.size()) {
        closesocket(s);
        return INVALID_SOCKET;
    }

    // 3. 读取并消费 SOCKS5 服务器应答
    char connHdr[4] = {};
    if (!RecvExact(s, connHdr, 4, nullptr) || (unsigned char)connHdr[0] != 0x05 || connHdr[1] != 0x00) {
        closesocket(s);
        return INVALID_SOCKET;
    }

    int atyp = connHdr[3];
    if (atyp == 0x01) {
        char dummy[6]; // 4 字节 IPv4 + 2 字节 Port
        if (!RecvExact(s, dummy, 6, nullptr)) { closesocket(s); return INVALID_SOCKET; }
    } else if (atyp == 0x04) {
        char dummy[18]; // 16 字节 IPv6 + 2 字节 Port
        if (!RecvExact(s, dummy, 18, nullptr)) { closesocket(s); return INVALID_SOCKET; }
    } else if (atyp == 0x03) {
        unsigned char dlen = 0;
        if (!RecvExact(s, (char*)&dlen, 1, nullptr)) { closesocket(s); return INVALID_SOCKET; }
        std::vector<char> dummy(dlen + 2);
        if (!RecvExact(s, dummy.data(), dlen + 2, nullptr)) { closesocket(s); return INVALID_SOCKET; }
    } else {
        closesocket(s);
        return INVALID_SOCKET;
    }

    return s;
}

SOCKET ProxyServer::ConnectToHttpProxy(const ProxyPort& port, const std::string& targetHost, int targetPort) {
    SOCKET s = ConnectDirect(port.upstreamHost, port.upstreamPort);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;

    std::ostringstream ss;
    ss << "CONNECT " << targetHost << ":" << targetPort << " HTTP/1.1\r\n"
       << "Host: " << targetHost << ":" << targetPort << "\r\n";
    if (!port.upstreamUser.empty()) {
        std::string auth = Utils::Base64Encode(port.upstreamUser + ":" + port.upstreamPass);
        ss << "Proxy-Authorization: Basic " << auth << "\r\n";
    }
    ss << "Proxy-Connection: Keep-Alive\r\n\r\n";

    std::string req = ss.str();
    if (send(s, req.c_str(), req.length(), 0) != (int)req.length()) { closesocket(s); return INVALID_SOCKET; }

    char buf[512] = {};
    int recvd = recv(s, buf, sizeof(buf) - 1, 0);
    if (recvd <= 0 || std::string(buf).find("200") == std::string::npos) {
        closesocket(s);
        return INVALID_SOCKET;
    }
    return s;
}

bool ProxyServer::CheckProxyConnectivity(const ProxyPort& port, int* outLatency) {
    auto start = std::chrono::steady_clock::now();
    SOCKET s = ConnectToUpstream(port, "www.google.com", 443);
    if (s == INVALID_SOCKET) {
        s = ConnectToUpstream(port, "www.bing.com", 443);
    }
    if (s != INVALID_SOCKET) {
        auto end = std::chrono::steady_clock::now();
        if (outLatency) {
            *outLatency = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        }
        closesocket(s);
        return true;
    }
    return false;
}

void ProxyServer::RelayData(SOCKET client, SOCKET upstream, int userId, int portId,
                           uint64_t connId, std::shared_ptr<OpenSSLSession> tlsSession) {
    int nodelay = 1;
    setsockopt(client, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
    setsockopt(upstream, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));

    std::string bufSizeStr = Database::Instance().GetConfig("relay_buffer_size_kb", "64");
    int bufSize = std::max(16, std::atoi(bufSizeStr.c_str())) * 1024;
    std::vector<char> buf1(bufSize);
    std::vector<char> buf2(bufSize);

    struct pollfd fds[2];
    fds[0].fd = client;
    fds[0].events = POLLIN;
    fds[1].fd = upstream;
    fds[1].events = POLLIN;

    int idleCount = 0;
    while (running_.load()) {
        if (connId != 0 && !RealtimeConnectionManager::Instance().IsActive(connId)) {
            break;
        }

        bool tlsHasPending = (tlsSession && tlsSession->HasPendingData());
        int timeoutMs = tlsHasPending ? 0 : 1000;

        int ret = poll(fds, 2, timeoutMs);
        if (ret < 0) {
            if (errno == EINTR) continue;
            break;
        }

        if (ret == 0 && !tlsHasPending) {
            idleCount++;
            if (idleCount >= 120) break; // 120s 空闲超时
            continue;
        }
        idleCount = 0;

        // 客户端 -> 上游
        if ((fds[0].revents & POLLIN) || tlsHasPending) {
            int n = RecvFromClient(client, buf1.data(), bufSize, tlsSession);
            if (n <= 0) break;
            int totalSent = 0;
            while (totalSent < n) {
                int sent = send(upstream, buf1.data() + totalSent, n - totalSent, 0);
                if (sent <= 0) break;
                totalSent += sent;
            }
            if (totalSent < n) break;
            TrafficMonitor::Instance().RecordUpload(userId, portId, n);
            RealtimeConnectionManager::Instance().RecordTraffic(connId, n, 0);
        }

        // 上游 -> 客户端
        if (fds[1].revents & POLLIN) {
            int n = recv(upstream, buf2.data(), bufSize, 0);
            if (n <= 0) break;
            int totalSent = 0;
            while (totalSent < n) {
                int sent = SendToClient(client, buf2.data() + totalSent, n - totalSent, tlsSession);
                if (sent <= 0) break;
                totalSent += sent;
            }
            if (totalSent < n) break;
            TrafficMonitor::Instance().RecordDownload(userId, portId, n);
            RealtimeConnectionManager::Instance().RecordTraffic(connId, 0, n);
        }

        if ((fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) ||
            (fds[1].revents & (POLLERR | POLLHUP | POLLNVAL))) {
            break;
        }
    }

    if (tlsSession) {
        tlsSession->Close();
    }
    RealtimeConnectionManager::Instance().CloseConnection(connId);
    closesocket(client);
    closesocket(upstream);
}
