#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include "ProxyServer.h"
#include "SchannelSession.h"

int SendToClient(SOCKET s, const char* buf, int len, std::shared_ptr<SchannelSession> tlsSession) {
    if (tlsSession) {
        return tlsSession->Write(s, buf, len);
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

int RecvFromClient(SOCKET s, char* buf, int len, std::shared_ptr<SchannelSession> tlsSession) {
    if (tlsSession) {
        return tlsSession->Read(s, buf, len);
    } else {
        return recv(s, buf, len, 0);
    }
}

#include "UserManager.h"
#include "TrafficMonitor.h"
#include "ConnectionLogger.h"
#include "RealtimeConnectionManager.h"
#include "XrayManager.h"
#include "ClashManager.h"
#include "Rules.h"
#include "Utils.h"
#include <sstream>
#include <regex>
#include <cstdlib>

#pragma comment(lib, "ws2_32.lib")

// 严格按指定字节数循环接收数据（防止 TCP 分包截断导致解析错误）
static bool RecvExact(SOCKET s, char* buf, int len) {
    int total = 0;
    while (total < len) {
        int r = recv(s, buf + total, len - total, 0);
        if (r <= 0) return false;
        total += r;
    }
    return true;
}

// 轻量级 DNS 缓存，避免对相同域名的重复阻塞解析
struct DnsCacheEntry {
    std::string ip;
    std::chrono::steady_clock::time_point expireTime;
};
static std::mutex s_dnsCacheMutex;
static std::map<std::string, DnsCacheEntry> s_dnsCache;

static std::string ResolveHostWithCache(const std::string& host) {
    if (host.empty()) return "";
    unsigned int tmp;
    if (inet_pton(AF_INET, host.c_str(), &tmp) == 1) {
        return host;
    }
    
    auto now = std::chrono::steady_clock::now();
    {
        std::lock_guard<std::mutex> lock(s_dnsCacheMutex);
        auto it = s_dnsCache.find(host);
        if (it != s_dnsCache.end()) {
            if (now < it->second.expireTime) {
                return it->second.ip;
            }
        }
    }
    
    struct addrinfo hints = {}, *res = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    std::string resolvedIP = "";
    
    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) == 0 && res) {
        char ipStr[INET_ADDRSTRLEN];
        struct sockaddr_in* ipv4 = (struct sockaddr_in*)res->ai_addr;
        inet_ntop(AF_INET, &(ipv4->sin_addr), ipStr, INET_ADDRSTRLEN);
        resolvedIP = ipStr;
        freeaddrinfo(res);
    }
    
    {
        std::lock_guard<std::mutex> lock(s_dnsCacheMutex);
        if (!resolvedIP.empty()) {
            s_dnsCache[host] = {resolvedIP, now + std::chrono::minutes(10)};
        } else {
            // 失败时记录负缓存 30 秒，防止重复同步阻塞 DNS 查询拖死工作线程
            s_dnsCache[host] = {"", now + std::chrono::seconds(30)};
        }
        if (s_dnsCache.size() > 2000) {
            s_dnsCache.clear();
        }
    }
    
    return resolvedIP;
}

// 对上游目标进行原生 TCP 握手测速 (毫秒级高精度，非阻塞，超时 2000ms)
static bool TcpPing(const std::string& host, int port, int timeoutMs, int* outLatency) {
    if (host.empty() || port <= 0) return false;
    
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return false;
    
    // 启用非阻塞模式
    unsigned long nonBlock = 1;
    ioctlsocket(sock, FIONBIO, &nonBlock);
    
    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    
    std::string ip = ResolveHostWithCache(host);
    if (ip.empty() || inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) != 1) {
        closesocket(sock);
        return false;
    }
    
    auto start = std::chrono::steady_clock::now();
    connect(sock, (sockaddr*)&addr, sizeof(addr));
    
    fd_set writeFds, errFds;
    FD_ZERO(&writeFds);
    FD_ZERO(&errFds);
    FD_SET(sock, &writeFds);
    FD_SET(sock, &errFds);
    
    timeval tv;
    tv.tv_sec = timeoutMs / 1000;
    tv.tv_usec = (timeoutMs % 1000) * 1000;
    
    int sel = select(0, nullptr, &writeFds, &errFds, &tv);
    if (sel > 0 && FD_ISSET(sock, &writeFds) && !FD_ISSET(sock, &errFds)) {
        int optErr = 0;
        int optLen = sizeof(optErr);
        if (getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&optErr, &optLen) == 0 && optErr == 0) {
            auto end = std::chrono::steady_clock::now();
            int ms = (int)std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
            closesocket(sock);
            if (outLatency) *outLatency = (ms > 0 ? ms : 1);
            return true;
        }
    }
    
    closesocket(sock);
    return false;
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
    running_ = true;
    startTime_.store((int64_t)time(nullptr));

    // 初始化 Schannel 凭据句柄
    SchannelSession::InitializeCredentials();
    
    // 初始化分流规则管理器
    RuleManager::Instance().Initialize();

    // 初始化 XrayManager 和 ClashManager
    XrayManager::Instance().Initialize();
    ClashManager::Instance().Initialize();
    
    // 方案四：统一拉起单一聚合 Mihomo 实例
    ClashManager::Instance().StartOrReloadUnified();
    
    auto ports = Database::Instance().GetEnabledProxyPorts();
    for (const auto& port : ports) {
        // 仅对具有本地入站监听端口的配置提前拉起对应内核（出站节点在流量到达或测速时按需拉起，避免并发启动过多进程卡顿）
        if (port.listenPort > 0) {
            // 如果是 xray 类型，启动对应的 xray 进程
            if (port.upstreamType == "xray" && !port.xrayConfig.empty()) {
                XrayConfig xConfig = XrayManager::ParseConfigJson(port.xrayConfig);
                int localPort = XrayManager::Instance().StartXray(port.id, xConfig);
                if (localPort > 0) {
                    Utils::Log("Xray started for port config " + std::to_string(port.id) + 
                               ", local SOCKS5: " + std::to_string(localPort));
                } else {
                    Utils::LogError("Failed to start xray for port config " + std::to_string(port.id));
                }
            }
            
            // 如果是 clash 类型，启动对应的 clash 进程
            if (port.upstreamType == "clash" && !port.clashConfig.empty()) {
                int localPort = ClashManager::Instance().StartClash(port.id, port.clashConfig);
                if (localPort > 0) {
                    Utils::Log("Clash started for port config " + std::to_string(port.id) + 
                               ", local SOCKS5: " + std::to_string(localPort));
                } else {
                    Utils::LogError("Failed to start clash for port config " + std::to_string(port.id));
                }
            }
        }
    }
    
    // 启动 Clash 订阅自动更新线程
    ClashManager::Instance().StartAutoUpdate();
    
    for (const auto& port : ports) {
        // 跳过监听端口为0的配置（仅用于路由规则，不启动本地监听）
        if (port.listenPort <= 0) {
            Utils::Log("Port config " + std::to_string(port.id) + " (" + port.description + 
                       ") has no listen port, skipping listener startup");
            continue;
        }
        
        SOCKET listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listenSocket == INVALID_SOCKET) {
            Utils::LogError("Failed to create socket for port " + std::to_string(port.listenPort));
            continue;
        }
        
        int opt = 1;
        setsockopt(listenSocket, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
        
        sockaddr_in addr = {};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port.listenPort);
        
        if (bind(listenSocket, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
            Utils::LogError("Failed to bind port " + std::to_string(port.listenPort));
            closesocket(listenSocket);
            continue;
        }
        
        if (listen(listenSocket, SOMAXCONN) == SOCKET_ERROR) {
            Utils::LogError("Failed to listen on port " + std::to_string(port.listenPort));
            closesocket(listenSocket);
            continue;
        }
        
        {
            std::lock_guard<std::mutex> lock(portsMutex_);
            listenSockets_[port.listenPort] = listenSocket;
            listenerThreads_[port.listenPort] = std::thread(&ProxyServer::ListenerThread, this, port);
        }
        
        Utils::Log("Listening on port " + std::to_string(port.listenPort));
    }
    
    StartAutoProxyListener();
    StartProxyChecker();
    
    return true;
}

void ProxyServer::Stop() {
    running_ = false;
    startTime_.store(0);
    StopProxyChecker();
    StopAutoProxyListener();
    
    // 停止 Clash 订阅自动更新
    ClashManager::Instance().StopAutoUpdate();
    
    // 停止所有代理进程
    XrayManager::Instance().StopAll();
    ClashManager::Instance().StopAll();
    
    // 步骤1：先在锁内关闭所有 listen socket，然后转移线程到临时容器
    std::map<int, std::thread> threadsToJoin;
    {
        std::lock_guard<std::mutex> lock(portsMutex_);
        for (auto& pair : listenSockets_) {
            closesocket(pair.second);
        }
        listenSockets_.clear();
        threadsToJoin.swap(listenerThreads_);
    }
    
    // 步骤2：在锁外 join 线程，避免死锁
    for (auto& pair : threadsToJoin) {
        if (pair.second.joinable()) {
            pair.second.join();
        }
    }
    
    // 释放 Schannel 凭据句柄
    SchannelSession::FreeCredentials();
}

void ProxyServer::ReloadPorts() {
    if (!running_.load()) return;
    Stop();
    Start();
}

std::vector<int> ProxyServer::GetListeningPorts() const {
    std::vector<int> ports;
    std::lock_guard<std::mutex> lock(portsMutex_);
    for (const auto& pair : listenSockets_) {
        ports.push_back(pair.first);
    }
    return ports;
}

void ProxyServer::ListenerThread(ProxyPort port) {
    SOCKET listenSocket;
    {
        std::lock_guard<std::mutex> lock(portsMutex_);
        auto it = listenSockets_.find(port.listenPort);
        if (it == listenSockets_.end()) return;
        listenSocket = it->second;
    }
    
    while (running_.load()) {
        sockaddr_in clientAddr;
        int addrLen = sizeof(clientAddr);
        SOCKET clientSocket = accept(listenSocket, (sockaddr*)&clientAddr, &addrLen);
        
        if (clientSocket == INVALID_SOCKET) {
            if (running_.load()) {
                Utils::LogError("Accept failed on port " + std::to_string(port.listenPort));
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            continue;
        }
        
        char ipStr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &clientAddr.sin_addr, ipStr, INET_ADDRSTRLEN);
        std::string clientAddrStr = std::string(ipStr) + ":" + std::to_string(ntohs(clientAddr.sin_port));
        
        // 限制最大并发连接数，防止线程爆炸导致内存溢出
        if (activeConnections_.load() >= 2000) {
            Utils::LogError("Max concurrent connections reached (2000), rejecting on port " + std::to_string(port.listenPort));
            closesocket(clientSocket);
            continue;
        }
        
        std::thread(&ProxyServer::HandleClient, this, clientSocket, clientAddrStr, port).detach();
    }
}

static bool ReadHttpRequestHeaders(SOCKET clientSocket, std::shared_ptr<SchannelSession> tlsSession,
                                   std::string& requestHeader, std::string& extraPayload) {
    requestHeader.clear();
    extraPayload.clear();
    
    char buffer[4096];
    
    // 循环读取，直到找到 \r\n\r\n 或 \n\n，或者超出了最大请求头长度（例如 64KB）
    while (requestHeader.size() < 65536) {
        int received = 0;
        if (tlsSession) {
            received = tlsSession->Read(clientSocket, buffer, sizeof(buffer));
        } else {
            received = recv(clientSocket, buffer, sizeof(buffer), 0);
        }
        
        if (received <= 0) {
            if (received == -2) { // Schannel WOULDBLOCK
                fd_set rfds;
                FD_ZERO(&rfds);
                FD_SET(clientSocket, &rfds);
                timeval tv = {5, 0};
                int sel = select(0, &rfds, nullptr, nullptr, &tv);
                if (sel > 0) continue;
            }
            break;
        }
        
        requestHeader.append(buffer, received);
        
        // 查找 HTTP 头结束标记 \r\n\r\n
        size_t headerEnd = requestHeader.find("\r\n\r\n");
        if (headerEnd != std::string::npos) {
            size_t delimLen = 4;
            extraPayload = requestHeader.substr(headerEnd + delimLen);
            requestHeader = requestHeader.substr(0, headerEnd + delimLen);
            return true;
        }
        
        // 兼容单 \n\n 换行
        headerEnd = requestHeader.find("\n\n");
        if (headerEnd != std::string::npos) {
            size_t delimLen = 2;
            extraPayload = requestHeader.substr(headerEnd + delimLen);
            requestHeader = requestHeader.substr(0, headerEnd + delimLen);
            return true;
        }
    }
    
    return !requestHeader.empty();
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

void ProxyServer::HandleClient(SOCKET clientSocket, const std::string& clientAddr, ProxyPort port) {
    activeConnections_++;
    
    // 启用 TCP_NODELAY 降低延迟，并调大 Socket 缓冲区
    int nodelay = 1;
    setsockopt(clientSocket, IPPROTO_TCP, TCP_NODELAY, (const char*)&nodelay, sizeof(nodelay));
    int sockBufSize = 262144; // 256KB
    setsockopt(clientSocket, SOL_SOCKET, SO_RCVBUF, (const char*)&sockBufSize, sizeof(sockBufSize));
    setsockopt(clientSocket, SOL_SOCKET, SO_SNDBUF, (const char*)&sockBufSize, sizeof(sockBufSize));
    
    // 设置客户端 socket 超时，防止慢连接攻击和线程永久阻塞
    DWORD clientTimeout = 30000; // 30秒
    setsockopt(clientSocket, SOL_SOCKET, SO_RCVTIMEO, (char*)&clientTimeout, sizeof(clientTimeout));
    setsockopt(clientSocket, SOL_SOCKET, SO_SNDTIMEO, (char*)&clientTimeout, sizeof(clientTimeout));
    
    char buffer[65536];

    // 使用PEEK模式查看第一个字节
    int peeked = recv(clientSocket, buffer, sizeof(buffer), MSG_PEEK);
    if (peeked <= 0) {
        closesocket(clientSocket);
        activeConnections_--;
        return;
    }
    
    // 获取允许的入站代理类型（支持组合，如 "http,socks5"）
    std::string allowedType = Database::Instance().GetConfig("inbound_proxy_type", "all");

    // 检查是否为SOCKS5 (0x05)
    if (buffer[0] == 0x05) {
        if (!CheckProxyTypeAllowed(allowedType, "socks5")) {
            Utils::LogError("Rejected SOCKS5 connection from " + clientAddr + ": server proxy type configured as " + allowedType);
            closesocket(clientSocket);
            activeConnections_--;
            return;
        }
        // SOCKS5处理 - 在函数内部进行握手与认证
        HandleSocks5Proxy(clientSocket, clientAddr, port, 0, "", "");
        activeConnections_--;
        return;
    }
    
    // 检查是否为 TLS 握手 (0x16)
    std::shared_ptr<SchannelSession> tlsSession = nullptr;
    std::string request;
    std::string extraPayload;
    
    if (buffer[0] == 0x16) {
        if (!CheckProxyTypeAllowed(allowedType, "https")) {
            Utils::LogError("Rejected HTTPS/TLS connection from " + clientAddr + ": server proxy type configured as " + allowedType);
            closesocket(clientSocket);
            activeConnections_--;
            return;
        }
        Utils::Log("TLS Client Hello detected from " + clientAddr);
        tlsSession = std::make_shared<SchannelSession>();
        if (!tlsSession->Handshake(clientSocket)) {
            Utils::LogError("TLS handshake failed for " + clientAddr);
            closesocket(clientSocket);
            activeConnections_--;
            return;
        }
        Utils::Log("TLS handshake succeeded for " + clientAddr);
        
        // 握手成功后循环读取直到完整 HTTP 请求头结束 (\r\n\r\n)
        if (!ReadHttpRequestHeaders(clientSocket, tlsSession, request, extraPayload)) {
            Utils::LogError("TLS Read failed after handshake for " + clientAddr);
            closesocket(clientSocket);
            activeConnections_--;
            return;
        }
        Utils::Log("TLS decrypted request (" + std::to_string(request.size()) + " bytes) from " + clientAddr + ": " + request.substr(0, 80));
    } else {
        if (!CheckProxyTypeAllowed(allowedType, "http")) {
            Utils::LogError("Rejected plain HTTP connection from " + clientAddr + ": server proxy type configured as " + allowedType);
            closesocket(clientSocket);
            activeConnections_--;
            return;
        }
        // HTTP 处理 - 循环读取直到完整 HTTP 请求头结束 (\r\n\r\n)
        if (!ReadHttpRequestHeaders(clientSocket, nullptr, request, extraPayload)) {
            closesocket(clientSocket);
            activeConnections_--;
            return;
        }
    }
    
    // 解析HTTP请求头，提取目标地址用于日志与认证头
    std::string authHeader;
    std::string targetHost = "";
    int targetPort = 0;
    std::istringstream iss(request);
    std::string line;
    std::string firstLine;
    bool isFirstLine = true;
    while (std::getline(iss, line)) {
        if (isFirstLine) {
            firstLine = line;
            isFirstLine = false;
            // 尝试解析目标地址
            std::istringstream lineStream(firstLine);
            std::string method, url;
            lineStream >> method >> url;
            if (method == "CONNECT") {
                size_t colonPos = url.find(':');
                if (colonPos != std::string::npos) {
                    targetHost = url.substr(0, colonPos);
                    targetPort = std::atoi(url.substr(colonPos + 1).c_str());
                }
            } else if (url.find("http://") == 0) {
                url = url.substr(7);
                size_t slashPos = url.find('/');
                std::string hostPort = (slashPos != std::string::npos) ? url.substr(0, slashPos) : url;
                size_t colonPos = hostPort.find(':');
                if (colonPos != std::string::npos) {
                    targetHost = hostPort.substr(0, colonPos);
                    targetPort = std::atoi(hostPort.substr(colonPos + 1).c_str());
                } else {
                    targetHost = hostPort;
                    targetPort = 80;
                }
            }
        }
        if (line.empty() || line == "\r") break;

        // 大小写不敏感解析 Proxy-Authorization 或 Authorization
        std::string lowerLine = line;
        for (char& c : lowerLine) c = (char)::tolower((unsigned char)c);
        
        if (lowerLine.find("proxy-authorization:") == 0) {
            size_t valueStart = 20;
            while (valueStart < line.size() && (line[valueStart] == ' ' || line[valueStart] == '\t')) {
                valueStart++;
            }
            authHeader = line.substr(valueStart);
            while (!authHeader.empty() && (authHeader.back() == '\r' || authHeader.back() == '\n' || ::isspace((unsigned char)authHeader.back()))) {
                authHeader.pop_back();
            }
        } else if (authHeader.empty() && lowerLine.find("authorization:") == 0) {
            size_t valueStart = 14;
            while (valueStart < line.size() && (line[valueStart] == ' ' || line[valueStart] == '\t')) {
                valueStart++;
            }
            authHeader = line.substr(valueStart);
            while (!authHeader.empty() && (authHeader.back() == '\r' || authHeader.back() == '\n' || ::isspace((unsigned char)authHeader.back()))) {
                authHeader.pop_back();
            }
        } else if (targetHost.empty() && lowerLine.find("host:") == 0) {
            size_t valueStart = 5;
            while (valueStart < line.size() && (line[valueStart] == ' ' || line[valueStart] == '\t')) {
                valueStart++;
            }
            std::string hostVal = line.substr(valueStart);
            while (!hostVal.empty() && (hostVal.back() == '\r' || hostVal.back() == '\n' || ::isspace((unsigned char)hostVal.back()))) {
                hostVal.pop_back();
            }
            size_t colonPos = hostVal.rfind(':');
            if (colonPos != std::string::npos) {
                targetHost = hostVal.substr(0, colonPos);
                targetPort = std::atoi(hostVal.substr(colonPos + 1).c_str());
            } else {
                targetHost = hostVal;
                targetPort = (tlsSession != nullptr) ? 443 : 80;
            }
        }
    }
    
    std::string clientIP = Utils::GetClientIP(clientAddr);
    
    // 增加 免认证IP 检查
    if (Database::Instance().IsNoAuthIP(clientIP)) {
        Utils::Log("No-Auth IP connection from: " + clientIP);
        // 使用内置的免认证用户 "no-auth"
        HandleHttpProxy(clientSocket, clientAddr, port, 0, "no-auth", request, extraPayload, tlsSession);
        activeConnections_--;
        return;
    }

    // 认证处理
    std::string username, password;
    UserInfo user;
    
    if (authHeader.empty() || !Utils::ParseBasicAuth(authHeader, username, password)) {
        // 先尝试通过IP直接使用免密账户登录
        if (UserManager::Instance().Authenticate("", "", clientIP, user)) {
            // 记录免密成功
            Utils::LogAuthSuccess(user.username, clientIP, "HTTP");
            HandleHttpProxy(clientSocket, clientAddr, port, user.id, user.username, request, extraPayload, tlsSession);
            activeConnections_--;
            return;
        }

        std::string inboundType = (tlsSession != nullptr) ? "HTTPS" : "HTTP";
        // 记录未认证请求
        ConnectionLogger::Instance().Log("", clientIP, targetHost, targetPort, "AUTH_REQUIRED", "", inboundType);
        
        // 返回407要求认证
        const char* response = "HTTP/1.1 407 Proxy Authentication Required\r\n"
                               "Proxy-Authenticate: Basic realm=\"ProxyRelay\"\r\n"
                               "Content-Length: 0\r\n\r\n";
        SendToClient(clientSocket, response, (int)strlen(response), tlsSession);
        closesocket(clientSocket);
        activeConnections_--;
        return;
    }
    
    if (!UserManager::Instance().Authenticate(username, password, clientIP, user)) {
        std::string inboundType = (tlsSession != nullptr) ? "HTTPS" : "HTTP";
        // 记录认证失败
        ConnectionLogger::Instance().Log(username, clientIP, targetHost, targetPort, "AUTH_FAILED", "", inboundType);
        Utils::LogAuthFailed(username, clientIP, "HTTP");
        
        const char* response = "HTTP/1.1 403 Forbidden\r\n"
                               "Content-Length: 0\r\n\r\n";
        SendToClient(clientSocket, response, (int)strlen(response), tlsSession);
        closesocket(clientSocket);
        activeConnections_--;
        return;
    }
    
    // 记录认证成功（首次）
    Utils::LogAuthSuccess(username, clientIP, "HTTP");
    
    // 将已读取的请求传递给HandleHttpProxy
    HandleHttpProxy(clientSocket, clientAddr, port, user.id, username, request, extraPayload, tlsSession);
    activeConnections_--;
}

void ProxyServer::HandleHttpProxy(SOCKET clientSocket, const std::string& clientAddr,
                                   const ProxyPort& port, int userId, const std::string& username,
                                   const std::string& initialRequest, const std::string& extraPayload,
                                   std::shared_ptr<SchannelSession> tlsSession) {
    // 解析请求行
    std::istringstream iss(initialRequest);
    std::string method, url, version;
    iss >> method >> url >> version;
    std::string inboundType = (tlsSession != nullptr || method == "CONNECT") ? "HTTPS" : "HTTP";
    
    std::string targetHost;
    int targetPort = 80;
    
    if (method == "CONNECT") {
        // HTTPS CONNECT
        size_t colonPos = url.find(':');
        if (colonPos != std::string::npos) {
            targetHost = url.substr(0, colonPos);
            targetPort = std::stoi(url.substr(colonPos + 1));
        } else {
            targetHost = url;
            targetPort = 443;
        }
    } else {
        // HTTP请求，解析URL
        static const std::regex urlRegex(R"(https?://([^/:]+)(?::(\d+))?(/.*)?)", std::regex::icase | std::regex::optimize);
        std::smatch match;
        if (std::regex_match(url, match, urlRegex)) {
            targetHost = match[1].str();
            if (match[2].matched) {
                targetPort = std::stoi(match[2].str());
            }
        } else if (!url.empty() && url[0] == '/') {
            // 相对路径 URL (透明代理或 TLS 解密代理)，从 Host 头部提取目标
            std::istringstream hStream(initialRequest);
            std::string hLine;
            while (std::getline(hStream, hLine)) {
                std::string lowerH = hLine;
                for (char& c : lowerH) c = (char)::tolower((unsigned char)c);
                if (lowerH.find("host:") == 0) {
                    size_t vs = 5;
                    while (vs < hLine.size() && (hLine[vs] == ' ' || hLine[vs] == '\t')) vs++;
                    std::string hVal = hLine.substr(vs);
                    while (!hVal.empty() && (hVal.back() == '\r' || hVal.back() == '\n' || ::isspace((unsigned char)hVal.back()))) {
                        hVal.pop_back();
                    }
                    size_t cp = hVal.rfind(':');
                    if (cp != std::string::npos) {
                        targetHost = hVal.substr(0, cp);
                        targetPort = std::atoi(hVal.substr(cp + 1).c_str());
                    } else {
                        targetHost = hVal;
                        targetPort = (tlsSession != nullptr) ? 443 : 80;
                    }
                    break;
                }
            }
        } else {
            Utils::LogError("Failed to parse URL: " + url);
            const char* response = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
            SendToClient(clientSocket, response, (int)strlen(response), tlsSession);
            closesocket(clientSocket);
            return;
        }
    }
    
    if (targetHost.empty()) {
        Utils::LogError("Empty target host for URL: " + url);
        const char* response = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
        SendToClient(clientSocket, response, (int)strlen(response), tlsSession);
        closesocket(clientSocket);
        return;
    }
    
    // 记录连接日志
    std::string clientIP = Utils::GetClientIP(clientAddr);
    std::string actualProxyDesc = port.description;
    
    // 检查用户的目标限制
    if (userId > 0) {
        UserInfo checkUser;
        if (Database::Instance().GetUser(userId, checkUser)) {
            if (!UserManager::IsTargetAllowed(targetHost, targetHost, checkUser.allowedTargets)) {
                Utils::Log("Target blocked by user policy: user=" + username + ", target=" + targetHost);
                ConnectionLogger::Instance().Log(username, clientIP, targetHost, targetPort, "BLOCKED", "User target policy", inboundType);
                const char* response = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
                SendToClient(clientSocket, response, (int)strlen(response), tlsSession);
                closesocket(clientSocket);
                return;
            }
        }
    }
    
    // 判断 targetHost 是否为 IP 地址
    std::string targetIP = "";
    std::string targetDomain = "";
    unsigned int tmpVal = 0;
    if (inet_pton(AF_INET, targetHost.c_str(), &tmpVal) == 1) {
        targetIP = targetHost;
    } else {
        targetDomain = targetHost;
    }
    
    // Check Blacklist (仅对已知的 IP 进行黑名单校验，避免阻塞域名解析)
    if (!targetIP.empty() && RuleManager::Instance().IsBlacklisted(targetIP)) {
        // 记录被黑名单阻止的请求
        ConnectionLogger::Instance().Log(username, clientIP, targetHost, targetPort, "BLOCKED", "Blacklist", inboundType);
        
        const char* response = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
        SendToClient(clientSocket, response, (int)strlen(response), tlsSession);
        closesocket(clientSocket);
        return;
    }
    
    // 检查路由规则，获取匹配的代理ID及分组（域名优先，无需本地DNS解析）
    // 返回值: 0=直连, >0=使用指定代理, -1=无匹配（使用旧的bypass逻辑）, -2=拒绝, -3=匹配到目标分组
    std::string matchedGroup;
    int matchedProxyId = RuleManager::Instance().GetMatchingProxyId(targetIP, targetDomain, &matchedGroup);
    
    // 拒绝规则：直接拒绝连接
    if (matchedProxyId == -2) {
        Utils::Log("Routing rule REJECT: " + targetHost);
        ConnectionLogger::Instance().Log(username, clientIP, targetHost, targetPort, "REJECTED", "Routing rule", inboundType);
        const char* response = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
        SendToClient(clientSocket, response, (int)strlen(response), tlsSession);
        closesocket(clientSocket);
        return;
    }
    
    bool bypass = false;
    bool strictBypass = false;  // 严格直连模式：直连失败不回退到代理
    ProxyPort targetProxy = port;  // 默认使用当前端口配置的上游代理
    
    if (matchedProxyId == 0) {
        // 直连规则全局有效 - 严格模式
        bypass = true;
        strictBypass = true;  // 路由规则指定的直连是严格的
        Utils::Log("Routing rule matched: direct connection for " + targetHost + " (strict mode)");
    } else if (matchedProxyId > 0) {
        // 代理规则匹配：ConnectWithFallback 会处理可用性检查和回退
        Utils::Log("Routing rule matched: using proxy " + std::to_string(matchedProxyId) + " for " + targetHost);
    } else if (matchedProxyId == -3) {
        // 目标分组匹配：ConnectWithFallback 会按组内优先级顺序选择可用节点
        Utils::Log("Routing rule matched: using group '" + matchedGroup + "' for " + targetHost);
    } else if (matchedProxyId == -1) {
        // 完全没有代理规则配置，使用旧的 bypass 逻辑（严格匹配域名/IP，绝对不对未知境外域名做同步阻塞解析）
        bypass = RuleManager::Instance().ShouldBypass(targetIP, targetDomain);
    }

    // 连接上游代理或直连
    SOCKET upstreamSocket = INVALID_SOCKET;
    int actualPortId = port.id;
    bool bypassFailed = false;  // 记录严格直连是否失败
    
    // Bypass: 直接连接目标
    if (bypass) {
        std::string connectIP = targetIP;
        if (connectIP.empty()) {
            connectIP = ResolveHostWithCache(targetDomain);
            if (connectIP.empty()) {
                Utils::Log("Bypass DNS resolution failed for: " + targetHost);
                bypass = false;
                if (strictBypass) bypassFailed = true;
            } else {
                Utils::Log("Bypass DNS resolved: " + targetHost + " -> " + connectIP);
            }
        }
        
        if (bypass && !connectIP.empty()) {
            Utils::Log("Attempting bypass direct connection to: " + connectIP + ":" + std::to_string(targetPort));
            SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (s != INVALID_SOCKET) {
                int nodelay = 1;
                setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char*)&nodelay, sizeof(nodelay));
                int sockBufSize = 262144;
                setsockopt(s, SOL_SOCKET, SO_RCVBUF, (const char*)&sockBufSize, sizeof(sockBufSize));
                setsockopt(s, SOL_SOCKET, SO_SNDBUF, (const char*)&sockBufSize, sizeof(sockBufSize));
                
                // 设置超时，避免长时间等待
                DWORD timeout = 5000;  // 5秒超时
                setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
                setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
                
                sockaddr_in addr = {};
                addr.sin_family = AF_INET;
                addr.sin_port = htons(targetPort);
                inet_pton(AF_INET, connectIP.c_str(), &addr.sin_addr);
                if (connect(s, (sockaddr*)&addr, sizeof(addr)) == 0) {
                    upstreamSocket = s;
                    actualProxyDesc = "Direct (Bypass)";
                    actualPortId = 0;
                    Utils::Log("Bypass direct connection successful to: " + connectIP);
                } else { 
                    int err = WSAGetLastError();
                    closesocket(s); 
                    bypass = false;
                    if (strictBypass) {
                        bypassFailed = true;
                        Utils::Log("Bypass connection failed to " + connectIP + ":" + std::to_string(targetPort) + 
                                   ", error=" + std::to_string(err) + ", strict mode - NOT falling back to proxy");
                    } else {
                        Utils::Log("Bypass connection failed to " + connectIP + ":" + std::to_string(targetPort) + 
                                   ", error=" + std::to_string(err) + ", falling back to proxy");
                    }
                }
            } else {
                bypass = false;
                if (strictBypass) bypassFailed = true;
            }
        }
    }

    // 严格直连模式下，如果直连失败，直接返回错误
    if (strictBypass && bypassFailed) {
        Utils::LogError("Strict bypass failed for " + targetHost + ", connection refused");
        const char* response = "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n";
        SendToClient(clientSocket, response, (int)strlen(response), tlsSession);
        closesocket(clientSocket);
        return;
    }

    // 如果不是 bypass 或 bypass 失败（非严格模式），使用代理
    if (!bypass && !strictBypass) {
        if (targetProxy.upstreamType == "auto" || matchedProxyId > 0 || matchedProxyId == -3) {
            // auto 类型或路由规则匹配到代理/分组：使用带回退的连接方式
            int proxyId = (matchedProxyId > 0) ? matchedProxyId : 0;
            auto connResult = ConnectWithFallback(proxyId, targetHost, targetPort, matchedGroup);
            upstreamSocket = connResult.socket;
            actualPortId = connResult.portId;
            actualProxyDesc = connResult.description;
        } else {
            // 非 auto 端口，使用端口自身配置的上游代理
            upstreamSocket = ConnectToProxyByType(targetProxy, targetHost, targetPort);
            actualPortId = targetProxy.id;
            actualProxyDesc = targetProxy.description;
        }
    }
    
    if (upstreamSocket == INVALID_SOCKET) {
        Utils::LogError("Failed to connect to upstream proxy for target " + targetHost);
        const char* response = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
        SendToClient(clientSocket, response, (int)strlen(response), tlsSession);
        closesocket(clientSocket);
        return;
    }
    
    if (method == "CONNECT") {
        // HTTPS隧道建立成功
        const char* response = "HTTP/1.1 200 Connection Established\r\n\r\n";
        SendToClient(clientSocket, response, (int)strlen(response), tlsSession);
        if (!extraPayload.empty()) {
            send(upstreamSocket, extraPayload.data(), (int)extraPayload.size(), 0);
        }
    } else {
        // 转发HTTP请求到上游（需要去除Proxy-Authorization头，转换绝对URL为相对URL）
        std::string modifiedRequest;
        
        // 解析路径部分
        std::string path = "/";
        {
            static const std::regex pathRegex(R"(https?://[^/]+(/.*)?)", std::regex::icase | std::regex::optimize);
            std::smatch pathMatch;
            if (std::regex_match(url, pathMatch, pathRegex)) {
                if (pathMatch[1].matched && !pathMatch[1].str().empty()) {
                    path = pathMatch[1].str();
                }
            } else if (!url.empty() && url[0] == '/') {
                path = url;
            }
        }
        
        // 构建相对URL请求
        modifiedRequest = method + " " + path + " " + version + "\r\n";
        
        // 复制除了Proxy-Authorization之外的其他头
        std::istringstream headerStream(initialRequest);
        std::string headerLine;
        bool firstLine = true;
        while (std::getline(headerStream, headerLine)) {
            if (firstLine) {
                firstLine = false;
                continue; // 跳过请求行
            }
            if (headerLine.empty() || headerLine == "\r") {
                modifiedRequest += "\r\n";
                break;
            }
            std::string lowerHeader = headerLine;
            for (char& c : lowerHeader) c = (char)::tolower((unsigned char)c);
            // 跳过Proxy-Authorization头
            if (lowerHeader.find("proxy-authorization:") != 0) {
                modifiedRequest += headerLine;
                if (headerLine.back() != '\n') {
                    modifiedRequest += "\n";
                }
            }
        }
        
        if (!extraPayload.empty()) {
            modifiedRequest += extraPayload;
        }
        
        send(upstreamSocket, modifiedRequest.c_str(), (int)modifiedRequest.length(), 0);
    }
    
    // 记录连接日志
    ConnectionLogger::Instance().Log(username, clientIP, targetHost, targetPort, method, actualProxyDesc, inboundType);

    // 注册实时连接
    uint64_t connId = RealtimeConnectionManager::Instance().AddConnection(username, clientIP, targetHost, targetPort, actualProxyDesc, inboundType);

    // 双向转发数据
    RelayData(clientSocket, upstreamSocket, userId, actualPortId, connId, tlsSession);

    // 关闭实时连接标记
    RealtimeConnectionManager::Instance().CloseConnection(connId);
    
    closesocket(upstreamSocket);
    closesocket(clientSocket);
}

SOCKET ProxyServer::ConnectToSocks5(const ProxyPort& port, const std::string& targetHost, int targetPort) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return INVALID_SOCKET;
    
    // 启用 TCP_NODELAY 并调大 Socket 缓冲区
    int nodelay = 1;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (const char*)&nodelay, sizeof(nodelay));
    int sockBufSize = 262144; // 256KB
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (const char*)&sockBufSize, sizeof(sockBufSize));
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (const char*)&sockBufSize, sizeof(sockBufSize));
    
    // 设置连接和收发超时，防止线程永久阻塞
    DWORD connTimeout = 5000; // 5秒超时
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&connTimeout, sizeof(connTimeout));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&connTimeout, sizeof(connTimeout));
    
    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port.upstreamPort);
    if (inet_pton(AF_INET, port.upstreamHost.c_str(), &addr.sin_addr) != 1) {
        struct addrinfo hints = {}, *res = nullptr;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(port.upstreamHost.c_str(), nullptr, &hints, &res) == 0 && res) {
            struct sockaddr_in* ipv4 = (struct sockaddr_in*)res->ai_addr;
            addr.sin_addr = ipv4->sin_addr;
            freeaddrinfo(res);
        } else {
            closesocket(sock);
            return INVALID_SOCKET;
        }
    }
    
    if (connect(sock, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(sock);
        return INVALID_SOCKET;
    }
    
    // SOCKS5握手
    unsigned char greeting[4] = {0x05, 0x02, 0x00, 0x02}; // 支持无认证和用户名密码
    send(sock, (char*)greeting, 4, 0);
    
    unsigned char response[2];
    if (!RecvExact(sock, (char*)response, 2)) {
        closesocket(sock);
        return INVALID_SOCKET;
    }
    
    if (response[0] != 0x05) {
        closesocket(sock);
        return INVALID_SOCKET;
    }
    
    // 认证
    if (response[1] == 0x02 && !port.upstreamUser.empty()) {
        std::vector<unsigned char> auth;
        auth.push_back(0x01);
        auth.push_back((unsigned char)port.upstreamUser.length());
        auth.insert(auth.end(), port.upstreamUser.begin(), port.upstreamUser.end());
        auth.push_back((unsigned char)port.upstreamPass.length());
        auth.insert(auth.end(), port.upstreamPass.begin(), port.upstreamPass.end());
        
        send(sock, (char*)auth.data(), (int)auth.size(), 0);
        
        unsigned char authResp[2];
        if (!RecvExact(sock, (char*)authResp, 2) || authResp[1] != 0x00) {
            closesocket(sock);
            return INVALID_SOCKET;
        }
    } else if (response[1] == 0xFF) {
        // 无可接受的认证方式
        closesocket(sock);
        return INVALID_SOCKET;
    }
    
    // 连接请求（IP用IPv4格式，域名用域名格式发向上游，让上游远程解析 DNS）
    std::vector<unsigned char> connectReq;
    connectReq.push_back(0x05);
    connectReq.push_back(0x01); // CONNECT
    connectReq.push_back(0x00);
    
    unsigned int ipv4Val = 0;
    if (inet_pton(AF_INET, targetHost.c_str(), &ipv4Val) == 1) {
        connectReq.push_back(0x01); // IPv4
        connectReq.insert(connectReq.end(), (unsigned char*)&ipv4Val, (unsigned char*)&ipv4Val + 4);
    } else {
        connectReq.push_back(0x03); // 域名
        connectReq.push_back((unsigned char)targetHost.length());
        connectReq.insert(connectReq.end(), targetHost.begin(), targetHost.end());
    }
    connectReq.push_back((targetPort >> 8) & 0xFF);
    connectReq.push_back(targetPort & 0xFF);
    
    send(sock, (char*)connectReq.data(), (int)connectReq.size(), 0);
    
    // 读取 SOCKS5 CONNECT 响应（变长）
    // 先读取4字节头部: VER, REP, RSV, ATYP
    unsigned char respHead[4];
    if (!RecvExact(sock, (char*)respHead, 4)) {
        closesocket(sock);
        return INVALID_SOCKET;
    }
    if (respHead[0] != 0x05 || respHead[1] != 0x00) {
        closesocket(sock);
        return INVALID_SOCKET;
    }
    // 根据地址类型确定剩余要读取的字节数
    int remaining = 0;
    if (respHead[3] == 0x01) { // IPv4: 4字节地址 + 2字节端口
        remaining = 6;
    } else if (respHead[3] == 0x03) { // 域名: 1字节长度 + N字节域名 + 2字节端口
        unsigned char domLen = 0;
        if (!RecvExact(sock, (char*)&domLen, 1)) { closesocket(sock); return INVALID_SOCKET; }
        remaining = domLen + 2;
    } else if (respHead[3] == 0x04) { // IPv6: 16字节地址 + 2字节端口
        remaining = 18;
    } else {
        closesocket(sock);
        return INVALID_SOCKET;
    }
    if (remaining > 0) {
        std::vector<char> discard(remaining);
        if (!RecvExact(sock, discard.data(), remaining)) {
            closesocket(sock);
            return INVALID_SOCKET;
        }
    }
    
    return sock;
}

SOCKET ProxyServer::ConnectToXray(const ProxyPort& port, const std::string& targetHost, int targetPort) {
    // 获取该端口对应的 xray 本地 SOCKS5 端口
    int localSocksPort = XrayManager::Instance().GetLocalSocksPort(port.id);
    
    if (localSocksPort <= 0) {
        // xray 可能没有启动或已崩溃，尝试重新启动
        if (!port.xrayConfig.empty()) {
            XrayConfig xConfig = XrayManager::ParseConfigJson(port.xrayConfig);
            localSocksPort = XrayManager::Instance().StartXray(port.id, xConfig);
        }
        
        if (localSocksPort <= 0) {
            Utils::LogError("Xray not running for port " + std::to_string(port.id));
            return INVALID_SOCKET;
        }
    }
    
    // 检查 xray 进程是否仍在运行
    if (!XrayManager::Instance().IsRunning(port.id)) {
        Utils::Log("Xray process died for port " + std::to_string(port.id) + ", restarting...");
        if (!port.xrayConfig.empty()) {
            XrayConfig xConfig = XrayManager::ParseConfigJson(port.xrayConfig);
            localSocksPort = XrayManager::Instance().StartXray(port.id, xConfig);
            if (localSocksPort <= 0) {
                Utils::LogError("Failed to restart xray for port " + std::to_string(port.id));
                return INVALID_SOCKET;
            }
        }
    }
    
    // 创建一个临时的 ProxyPort 指向本地 xray 的 SOCKS5 入口
    ProxyPort localProxy;
    localProxy.upstreamHost = "127.0.0.1";
    localProxy.upstreamPort = localSocksPort;
    localProxy.upstreamUser = "";
    localProxy.upstreamPass = "";
    
    return ConnectToSocks5(localProxy, targetHost, targetPort);
}

SOCKET ProxyServer::ConnectToClash(const ProxyPort& port, const std::string& targetHost, int targetPort) {
    int localSocksPort = ClashManager::Instance().GetLocalSocksPort(port.id);
    
    if (localSocksPort <= 0) {
        if (!port.clashConfig.empty()) {
            localSocksPort = ClashManager::Instance().StartClash(port.id, port.clashConfig);
        }
        
        if (localSocksPort <= 0) {
            Utils::LogError("Clash not running for port " + std::to_string(port.id));
            return INVALID_SOCKET;
        }
    }
    
    if (!ClashManager::Instance().IsRunning(port.id)) {
        Utils::Log("Clash process died for port " + std::to_string(port.id) + ", restarting...");
        if (!port.clashConfig.empty()) {
            localSocksPort = ClashManager::Instance().StartClash(port.id, port.clashConfig);
            if (localSocksPort <= 0) {
                Utils::LogError("Failed to restart clash for port " + std::to_string(port.id));
                return INVALID_SOCKET;
            }
        }
    }
    
    ProxyPort localProxy;
    localProxy.upstreamHost = "127.0.0.1";
    localProxy.upstreamPort = localSocksPort;
    localProxy.upstreamUser = "";
    localProxy.upstreamPass = "";
    
    return ConnectToSocks5(localProxy, targetHost, targetPort);
}

SOCKET ProxyServer::ConnectToHttpProxy(const ProxyPort& port, const std::string& targetHost, int targetPort) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return INVALID_SOCKET;
    
    // 启用 TCP_NODELAY 并调大 Socket 缓冲区
    int nodelay = 1;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (const char*)&nodelay, sizeof(nodelay));
    int sockBufSize = 262144; // 256KB
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (const char*)&sockBufSize, sizeof(sockBufSize));
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (const char*)&sockBufSize, sizeof(sockBufSize));
    
    // 设置连接和收发超时，防止线程永久阻塞
    DWORD connTimeout = 10000; // 10秒
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&connTimeout, sizeof(connTimeout));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&connTimeout, sizeof(connTimeout));
    
    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port.upstreamPort);
    if (inet_pton(AF_INET, port.upstreamHost.c_str(), &addr.sin_addr) != 1) {
        struct addrinfo hints = {}, *res = nullptr;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(port.upstreamHost.c_str(), nullptr, &hints, &res) == 0 && res) {
            struct sockaddr_in* ipv4 = (struct sockaddr_in*)res->ai_addr;
            addr.sin_addr = ipv4->sin_addr;
            freeaddrinfo(res);
        } else {
            closesocket(sock);
            return INVALID_SOCKET;
        }
    }
    
    if (connect(sock, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(sock);
        return INVALID_SOCKET;
    }
    
    // 发送CONNECT请求
    std::ostringstream oss;
    oss << "CONNECT " << targetHost << ":" << targetPort << " HTTP/1.1\r\n";
    oss << "Host: " << targetHost << ":" << targetPort << "\r\n";
    
    if (!port.upstreamUser.empty()) {
        std::string auth = port.upstreamUser + ":" + port.upstreamPass;
        oss << "Proxy-Authorization: Basic " << Utils::Base64Encode(auth) << "\r\n";
    }
    oss << "\r\n";
    
    std::string request = oss.str();
    send(sock, request.c_str(), (int)request.length(), 0);
    
    char buffer[1024];
    int received = recv(sock, buffer, sizeof(buffer) - 1, 0);
    if (received <= 0) {
        closesocket(sock);
        return INVALID_SOCKET;
    }
    
    buffer[received] = '\0';
    if (strstr(buffer, "200") == nullptr) {
        closesocket(sock);
        return INVALID_SOCKET;
    }
    
    return sock;
}

void ProxyServer::RelayData(SOCKET client, SOCKET upstream, int userId, int portId, uint64_t connId,
                            std::shared_ptr<SchannelSession> tlsSession) {
    // 启用 TCP_NODELAY 与 256KB Socket 缓冲区，最大化吞吐
    int nodelay = 1;
    setsockopt(client, IPPROTO_TCP, TCP_NODELAY, (const char*)&nodelay, sizeof(nodelay));
    setsockopt(upstream, IPPROTO_TCP, TCP_NODELAY, (const char*)&nodelay, sizeof(nodelay));
    int sockBufSize = 262144; // 256KB
    setsockopt(client, SOL_SOCKET, SO_RCVBUF, (const char*)&sockBufSize, sizeof(sockBufSize));
    setsockopt(client, SOL_SOCKET, SO_SNDBUF, (const char*)&sockBufSize, sizeof(sockBufSize));
    setsockopt(upstream, SOL_SOCKET, SO_RCVBUF, (const char*)&sockBufSize, sizeof(sockBufSize));
    setsockopt(upstream, SOL_SOCKET, SO_SNDBUF, (const char*)&sockBufSize, sizeof(sockBufSize));

    // 确保为阻塞模式
    u_long nonBlocking = 0;
    ioctlsocket(client, FIONBIO, &nonBlocking);
    ioctlsocket(upstream, FIONBIO, &nonBlocking);

    // 动态读取配置的转发缓冲区大小并分配在堆上，防止大并发下线程栈溢出
    std::string bufKbStr = Database::Instance().GetConfig("relay_buffer_size_kb", "64");
    int bufKb = std::atoi(bufKbStr.c_str());
    if (bufKb < 16) bufKb = 16;
    if (bufKb > 512) bufKb = 512;
    size_t bufSize = (size_t)bufKb * 1024;
    std::vector<char> bufferVec(bufSize);
    char* buffer = bufferVec.data();
    
    DWORD timeout = 30000;
    setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(upstream, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(upstream, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
    
    int idleCount = 0;
    uint64_t bytesTransferredSinceLimitCheck = 0;
    const uint64_t LIMIT_CHECK_INTERVAL = 1048576; // 每传输 1MB 检查一次用户限额，防止长连接无限绕过限额

    fd_set readfds;
    while (running_.load()) {
        if (connId != 0 && !RealtimeConnectionManager::Instance().IsActive(connId)) {
            break;
        }
        bool tlsHasPending = (tlsSession && tlsSession->HasPendingData());
        
        FD_ZERO(&readfds);
        FD_SET(client, &readfds);
        FD_SET(upstream, &readfds);
        
        timeval tv = {1, 0};
        if (tlsHasPending) {
            tv = {0, 0};
        }
        int ret = select(0, &readfds, nullptr, nullptr, &tv);
        
        if (ret < 0) {
            int err = WSAGetLastError();
            if (err == WSAEINTR) continue;
            break;
        }
        if (ret == 0 && !tlsHasPending) {
            idleCount++;
            if (idleCount >= 120) break; // 2分钟无数据自动关闭空闲连接
            continue;
        }
        idleCount = 0;
        
        // 客户端 -> 上游
        if (FD_ISSET(client, &readfds) || tlsHasPending) {
            int received = RecvFromClient(client, buffer, (int)bufSize, tlsSession);
            if (received <= 0) break;
            
            TrafficMonitor::Instance().RecordUpload(userId, portId, received);
            RealtimeConnectionManager::Instance().RecordTraffic(connId, received, 0);
            
            int totalSent = 0;
            while (totalSent < received) {
                int sent = send(upstream, buffer + totalSent, received - totalSent, 0);
                if (sent <= 0) break;
                totalSent += sent;
            }
            if (totalSent < received) break;

            if (userId > 0) {
                bytesTransferredSinceLimitCheck += (uint64_t)received;
                if (bytesTransferredSinceLimitCheck >= LIMIT_CHECK_INTERVAL) {
                    bytesTransferredSinceLimitCheck = 0;
                    if (!UserManager::Instance().CheckTrafficLimit(userId)) {
                        Utils::Log("User traffic limit exceeded during relay: userId=" + std::to_string(userId));
                        break;
                    }
                }
            }
        }
        
        // 上游 -> 客户端
        if (FD_ISSET(upstream, &readfds)) {
            int received = recv(upstream, buffer, (int)bufSize, 0);
            if (received <= 0) break;
            
            TrafficMonitor::Instance().RecordDownload(userId, portId, received);
            RealtimeConnectionManager::Instance().RecordTraffic(connId, 0, received);
            
            int totalSent = 0;
            while (totalSent < received) {
                int sent = SendToClient(client, buffer + totalSent, received - totalSent, tlsSession);
                if (sent <= 0) break;
                totalSent += sent;
            }
            if (totalSent < received) break;

            if (userId > 0) {
                bytesTransferredSinceLimitCheck += (uint64_t)received;
                if (bytesTransferredSinceLimitCheck >= LIMIT_CHECK_INTERVAL) {
                    bytesTransferredSinceLimitCheck = 0;
                    if (!UserManager::Instance().CheckTrafficLimit(userId)) {
                        Utils::Log("User traffic limit exceeded during relay: userId=" + std::to_string(userId));
                        break;
                    }
                }
            }
        }
    }
}

void ProxyServer::HandleSocks5Proxy(SOCKET clientSocket, const std::string& clientAddr,
                                     const ProxyPort& port, int userId, const std::string& username,
                                     const std::string& initialData) {
    std::string clientIP = Utils::GetClientIP(clientAddr);
    
    // 1. SOCKS5 握手 (客户端发送支持的认证方式)
    unsigned char greetingHeader[2];
    if (!initialData.empty()) {
        if (initialData.size() < 2) {
            closesocket(clientSocket);
            return;
        }
        greetingHeader[0] = (unsigned char)initialData[0];
        greetingHeader[1] = (unsigned char)initialData[1];
    } else {
        if (!RecvExact(clientSocket, (char*)greetingHeader, 2)) {
            closesocket(clientSocket);
            return;
        }
    }
    
    if (greetingHeader[0] != 0x05 || greetingHeader[1] == 0) {
        closesocket(clientSocket);
        return;
    }
    
    int numMethods = greetingHeader[1];
    std::vector<unsigned char> methods(numMethods);
    if (!initialData.empty()) {
        if (initialData.size() < (size_t)(2 + numMethods)) {
            closesocket(clientSocket);
            return;
        }
        memcpy(methods.data(), initialData.data() + 2, numMethods);
    } else {
        if (!RecvExact(clientSocket, (char*)methods.data(), numMethods)) {
            closesocket(clientSocket);
            return;
        }
    }
    
    bool supportsNoAuth = false;
    bool supportsUserPass = false;
    for (int i = 0; i < numMethods; i++) {
        if (methods[i] == 0x00) supportsNoAuth = true;
        if (methods[i] == 0x02) supportsUserPass = true;
    }
    
    int currentUserId = userId;
    std::string authUsername = username;
    UserInfo user;
    
    // 检查免认证 IP 或已有免密策略 (仅当客户端协商方法中包含 0x00 免密时)
    if (supportsNoAuth && (Database::Instance().IsNoAuthIP(clientIP) || UserManager::Instance().Authenticate("", "", clientIP, user))) {
        if (user.id > 0) {
            currentUserId = user.id;
            authUsername = user.username;
        } else {
            authUsername = "no-auth";
        }
        unsigned char response[] = {0x05, 0x00}; // 无需认证
        send(clientSocket, (char*)response, 2, 0);
    } else if (supportsUserPass) {
        // 通知客户端选择用户名/密码认证
        unsigned char response[] = {0x05, 0x02};
        send(clientSocket, (char*)response, 2, 0);
        
        // 2. 认证: 客户端发送用户名和密码 (RFC 1929)
        unsigned char authHeader[2];
        if (!RecvExact(clientSocket, (char*)authHeader, 2) || authHeader[0] != 0x01) {
            closesocket(clientSocket);
            return;
        }
        
        int ulen = authHeader[1];
        std::string reqUser(ulen, '\0');
        if (ulen > 0) {
            if (!RecvExact(clientSocket, &reqUser[0], ulen)) {
                closesocket(clientSocket);
                return;
            }
        }
        
        unsigned char plen = 0;
        if (!RecvExact(clientSocket, (char*)&plen, 1)) {
            closesocket(clientSocket);
            return;
        }
        
        std::string reqPass(plen, '\0');
        if (plen > 0) {
            if (!RecvExact(clientSocket, &reqPass[0], plen)) {
                closesocket(clientSocket);
                return;
            }
        }
        
        if (!UserManager::Instance().Authenticate(reqUser, reqPass, clientIP, user)) {
            // 记录 SOCKS5 认证失败
            ConnectionLogger::Instance().Log(reqUser, clientIP, "", 0, "SOCKS5_AUTH_FAILED", "", "SOCKS5");
            Utils::LogAuthFailed(reqUser, clientIP, "SOCKS5");
            
            // 认证失败响应 (Status != 0)
            char authResponse[] = {0x01, 0x01};
            send(clientSocket, authResponse, 2, 0);
            closesocket(clientSocket);
            return;
        }
        
        // 记录认证成功
        Utils::LogAuthSuccess(reqUser, clientIP, "SOCKS5");
        
        // 认证成功响应
        char authResponse[] = {0x01, 0x00};
        send(clientSocket, authResponse, 2, 0);
        currentUserId = user.id;
        authUsername = user.username;
    } else {
        // 无可接受的方法
        unsigned char response[] = {0x05, 0xFF};
        send(clientSocket, (char*)response, 2, 0);
        closesocket(clientSocket);
        return;
    }
    
    // 3. 请求: 客户端发送连接请求 (RFC 1928)
    unsigned char reqHeader[4];
    if (!RecvExact(clientSocket, (char*)reqHeader, 4)) {
        closesocket(clientSocket);
        return;
    }
    if (reqHeader[0] != 0x05) {
        closesocket(clientSocket);
        return;
    }
    if (reqHeader[1] != 0x01) { // 仅支持 CONNECT (0x01)
        char resp[] = {0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0}; // Command not supported
        send(clientSocket, resp, 10, 0);
        closesocket(clientSocket);
        return;
    }
    
    std::string targetHost;
    int targetPort = 0;
    
    // 解析目标地址
    if (reqHeader[3] == 0x01) { // IPv4
        unsigned char ipAndPort[6];
        if (!RecvExact(clientSocket, (char*)ipAndPort, 6)) {
            closesocket(clientSocket);
            return;
        }
        char ipStr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, ipAndPort, ipStr, INET_ADDRSTRLEN);
        targetHost = ipStr;
        targetPort = ntohs(*(unsigned short*)(ipAndPort + 4));
    } else if (reqHeader[3] == 0x03) { // Domain name
        unsigned char domLen = 0;
        if (!RecvExact(clientSocket, (char*)&domLen, 1) || domLen == 0) {
            closesocket(clientSocket);
            return;
        }
        std::string dom(domLen, '\0');
        if (!RecvExact(clientSocket, &dom[0], domLen)) {
            closesocket(clientSocket);
            return;
        }
        unsigned short netPort = 0;
        if (!RecvExact(clientSocket, (char*)&netPort, 2)) {
            closesocket(clientSocket);
            return;
        }
        targetHost = dom;
        targetPort = ntohs(netPort);
    } else if (reqHeader[3] == 0x04) { // IPv6
        char resp[] = {0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0}; // Address type not supported
        send(clientSocket, resp, 10, 0);
        closesocket(clientSocket);
        return;
    } else {
        char resp[] = {0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
        send(clientSocket, resp, 10, 0);
        closesocket(clientSocket);
        return;
    }
    
    std::string actualProxyDesc = port.description;
    
    // 检查用户的目标限制
    if (currentUserId > 0) {
        UserInfo checkUser;
        if (Database::Instance().GetUser(currentUserId, checkUser)) {
            if (!UserManager::IsTargetAllowed(targetHost, targetHost, checkUser.allowedTargets)) {
                Utils::Log("SOCKS5 target blocked by user policy: user=" + authUsername + ", target=" + targetHost);
                ConnectionLogger::Instance().Log(authUsername, clientIP, targetHost, targetPort, "BLOCKED", "User target policy", "SOCKS5");
                char resp[] = {0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
                send(clientSocket, resp, 10, 0);
                closesocket(clientSocket);
                return;
            }
        }
    }
    
    // 连接上游或目标
    SOCKET upstreamSocket = INVALID_SOCKET;
    int actualPortId = port.id;

    // 规则检查（域名优先，无需本地 DNS 解析）
    std::string targetIP = "";
    std::string targetDomain = "";
    unsigned int tmpVal2 = 0;
    if (inet_pton(AF_INET, targetHost.c_str(), &tmpVal2) == 1) {
        targetIP = targetHost;
    } else {
        targetDomain = targetHost;
    }
    
    if (!targetIP.empty() && RuleManager::Instance().IsBlacklisted(targetIP)) {
        // 记录被黑名单阻止的 SOCKS5 请求
        ConnectionLogger::Instance().Log(authUsername, clientIP, targetHost, targetPort, "BLOCKED", "Blacklist", "SOCKS5");
        char resp[] = {0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0}; 
        send(clientSocket, resp, 10, 0);
        closesocket(clientSocket);
        return;
    }
    
    // 检查路由规则，获取匹配的代理ID及分组（域名优先，无需本地DNS解析）
    std::string matchedGroup;
    int matchedProxyId = RuleManager::Instance().GetMatchingProxyId(targetIP, targetDomain, &matchedGroup);
    
    // 拒绝规则：直接拒绝连接
    if (matchedProxyId == -2) {
        Utils::Log("Routing rule REJECT (SOCKS5): " + targetHost);
        ConnectionLogger::Instance().Log(authUsername, clientIP, targetHost, targetPort, "REJECTED", "Routing rule", "SOCKS5");
        char resp[] = {0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0};  // 0x02 = connection not allowed by ruleset
        send(clientSocket, resp, 10, 0);
        closesocket(clientSocket);
        return;
    }
    
    bool bypass = false;
    bool strictBypass = false;  // 严格直连模式
    ProxyPort targetProxy = port;  // 默认使用当前端口配置的上游代理
    
    if (matchedProxyId == 0) {
        // 直连规则全局有效 - 严格模式
        bypass = true;
        strictBypass = true;
        Utils::Log("Routing rule matched: direct connection for " + targetHost + " (strict mode)");
    } else if (matchedProxyId > 0) {
        // 代理规则匹配：ConnectWithFallback 会处理可用性检查和回退
        Utils::Log("Routing rule matched: using proxy " + std::to_string(matchedProxyId) + " for " + targetHost);
    } else if (matchedProxyId == -3) {
        // 目标分组匹配：ConnectWithFallback 会按组内优先级顺序选择可用节点
        Utils::Log("Routing rule matched: using group '" + matchedGroup + "' for " + targetHost);
    } else if (matchedProxyId == -1) {
        // 完全没有代理规则配置，使用旧的 bypass 逻辑（绝对不对未知境外域名进行本地同步阻塞解析）
        bypass = RuleManager::Instance().ShouldBypass(targetIP, targetDomain);
    }
    
    bool bypassFailed = false;  // 记录严格直连是否失败
    
    if (bypass) {
        std::string connectIP = targetIP;
        if (connectIP.empty()) {
            connectIP = ResolveHostWithCache(targetDomain);
            if (connectIP.empty()) {
                Utils::Log("Bypass DNS resolution failed for: " + targetHost);
                bypass = false;
                if (strictBypass) bypassFailed = true;
            } else {
                Utils::Log("Bypass DNS resolved: " + targetHost + " -> " + connectIP);
            }
        }
        
        if (bypass && !connectIP.empty()) {
            Utils::Log("Attempting bypass direct connection to: " + connectIP + ":" + std::to_string(targetPort));
            SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (s != INVALID_SOCKET) {
                int nodelay = 1;
                setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char*)&nodelay, sizeof(nodelay));
                int sockBufSize = 262144;
                setsockopt(s, SOL_SOCKET, SO_RCVBUF, (const char*)&sockBufSize, sizeof(sockBufSize));
                setsockopt(s, SOL_SOCKET, SO_SNDBUF, (const char*)&sockBufSize, sizeof(sockBufSize));
                
                // 设置超时，避免长时间等待
                DWORD timeout = 5000;  // 5秒超时
                setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
                setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
                
                sockaddr_in addr = {};
                addr.sin_family = AF_INET;
                addr.sin_port = htons(targetPort);
                inet_pton(AF_INET, connectIP.c_str(), &addr.sin_addr);
                
                if (connect(s, (sockaddr*)&addr, sizeof(addr)) == 0) {
                    upstreamSocket = s;
                    actualProxyDesc = "Direct (Bypass)";
                    actualPortId = 0;
                    Utils::Log("Bypass direct connection successful to: " + connectIP);
                } else {
                    int err = WSAGetLastError();
                    closesocket(s);
                    bypass = false;
                    if (strictBypass) {
                        bypassFailed = true;
                        Utils::Log("Bypass connection failed to " + connectIP + ":" + std::to_string(targetPort) + 
                                   ", error=" + std::to_string(err) + ", strict mode - NOT falling back to proxy");
                    } else {
                        Utils::Log("Bypass connection failed to " + connectIP + ":" + std::to_string(targetPort) + 
                                   ", error=" + std::to_string(err) + ", falling back to proxy");
                    }
                }
            } else {
                bypass = false;
                if (strictBypass) bypassFailed = true;
            }
        }
    }
    
    // 严格直连模式下，如果直连失败，直接返回错误
    if (strictBypass && bypassFailed) {
        Utils::LogError("Strict bypass failed for " + targetHost + ", connection refused");
        char resp[] = {0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0}; // Connection refused
        send(clientSocket, resp, 10, 0);
        closesocket(clientSocket);
        return;
    }

    // 如果不是 bypass 或 bypass 失败（非严格模式），使用代理
    if (upstreamSocket == INVALID_SOCKET && !strictBypass) {
        if (targetProxy.upstreamType == "auto" || matchedProxyId > 0 || matchedProxyId == -3) {
            // auto 类型或路由规则匹配到代理/分组：使用带回退的连接方式
            int proxyId = (matchedProxyId > 0) ? matchedProxyId : 0;
            auto connResult = ConnectWithFallback(proxyId, targetHost, targetPort, matchedGroup);
            upstreamSocket = connResult.socket;
            actualPortId = connResult.portId;
            actualProxyDesc = connResult.description;
        } else {
            // 非 auto 端口，使用端口自身配置的上游代理
            upstreamSocket = ConnectToProxyByType(targetProxy, targetHost, targetPort);
            actualPortId = targetProxy.id;
            actualProxyDesc = targetProxy.description;
        }
    }
    
    if (upstreamSocket == INVALID_SOCKET) {
        char resp[] = {0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0}; // Connection refused
        send(clientSocket, resp, 10, 0);
        closesocket(clientSocket);
        return;
    }
    
    // 响应客户端: 成功
    char resp[] = {0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
    send(clientSocket, resp, 10, 0);
    
    // 记录连接日志
    ConnectionLogger::Instance().Log(authUsername, clientIP, targetHost, targetPort, "SOCKS5 CONNECT", actualProxyDesc, "SOCKS5");

    // 注册实时连接
    uint64_t connId = RealtimeConnectionManager::Instance().AddConnection(authUsername, clientIP, targetHost, targetPort, actualProxyDesc, "SOCKS5");

    // 开始转发流量
    RelayData(clientSocket, upstreamSocket, currentUserId, actualPortId, connId);

    // 关闭实时连接标记
    RealtimeConnectionManager::Instance().CloseConnection(connId);
    
    closesocket(upstreamSocket);
    closesocket(clientSocket);
}

void ProxyServer::StartAutoProxyListener() {
    StopAutoProxyListener();
    
    std::string portStr = Database::Instance().GetConfig("auto_proxy_port", "0");
    int port = std::atoi(portStr.c_str());
    
    if (port <= 0 || port > 65535) return;
    
    SOCKET listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSocket == INVALID_SOCKET) {
        Utils::LogError("Failed to create socket for auto proxy port " + std::to_string(port));
        return;
    }
    
    int opt = 1;
    setsockopt(listenSocket, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
    
    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    
    if (bind(listenSocket, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        Utils::LogError("Failed to bind auto proxy port " + std::to_string(port));
        closesocket(listenSocket);
        return;
    }
    
    if (listen(listenSocket, SOMAXCONN) == SOCKET_ERROR) {
        Utils::LogError("Failed to listen on auto proxy port " + std::to_string(port));
        closesocket(listenSocket);
        return;
    }
    
    autoProxySocket_ = listenSocket;
    
    ProxyPort autoPort;
    autoPort.id = 0;
    autoPort.listenPort = port;
    autoPort.upstreamType = "auto";
    autoPort.description = "Auto (Smart Routing)";
    
    autoProxyThread_ = std::thread([this, listenSocket, autoPort]() {
        while (running_.load()) {
            sockaddr_in clientAddr;
            int addrLen = sizeof(clientAddr);
            SOCKET clientSocket = accept(listenSocket, (sockaddr*)&clientAddr, &addrLen);
            
            if (clientSocket == INVALID_SOCKET) {
                if (running_.load()) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                }
                continue;
            }
            
            char ipStr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &clientAddr.sin_addr, ipStr, INET_ADDRSTRLEN);
            std::string clientAddrStr = std::string(ipStr) + ":" + std::to_string(ntohs(clientAddr.sin_port));
            
            // 限制最大并发连接数，防止线程爆炸导致内存溢出
            if (activeConnections_.load() >= 2000) {
                Utils::LogError("Max concurrent connections reached (2000), rejecting on auto proxy port " + std::to_string(autoPort.listenPort));
                closesocket(clientSocket);
                continue;
            }
            
            std::thread(&ProxyServer::HandleClient, this, clientSocket, clientAddrStr, autoPort).detach();
        }
    });
    
    Utils::Log("Auto Proxy listening on port " + std::to_string(port));
}

void ProxyServer::StopAutoProxyListener() {
    SOCKET s = autoProxySocket_.exchange(INVALID_SOCKET);
    if (s != INVALID_SOCKET) {
        closesocket(s);
    }
    if (autoProxyThread_.joinable()) {
        autoProxyThread_.join();
    }
}

void ProxyServer::StartProxyChecker() {
    if (checkerRunning_.load()) {
        return;
    }
    if (checkerThread_.joinable()) {
        checkerThread_.join();
    }
    checkerRunning_ = true;
    checkerThread_ = std::thread(&ProxyServer::CheckerThread, this);
}

void ProxyServer::StopProxyChecker() {
    checkerRunning_ = false;
    checkerCv_.notify_all();
    if (checkerThread_.joinable()) {
        checkerThread_.join();
    }
    std::lock_guard<std::mutex> lock(statusMutex_);
    proxyStatus_.clear();
}

void ProxyServer::TriggerCheck() {
    triggerCheck_ = true;
    checkerCv_.notify_all();
}

bool ProxyServer::IsProxyAvailable(int portId) {
    std::lock_guard<std::mutex> lock(statusMutex_);
    auto it = proxyStatus_.find(portId);
    if (it != proxyStatus_.end()) {
        return it->second.isAvailable;
    }
    return true; // 默认可用
}

int ProxyServer::GetProxyLatency(int portId) {
    std::lock_guard<std::mutex> lock(statusMutex_);
    auto it = proxyStatus_.find(portId);
    if (it != proxyStatus_.end()) {
        return it->second.latency;
    }
    return -1;
}

void ProxyServer::UpdateProxyStatus(int portId, bool available, int latency) {
    std::lock_guard<std::mutex> lock(statusMutex_);
    auto& st = proxyStatus_[portId];
    st.isAvailable = available;
    st.latency = available ? latency : -1;
}

void ProxyServer::CheckerThread() {
    while (checkerRunning_.load()) {
        // 定期检查 HTTPS 证书有效期并在临期不足24小时时自动检测并热更新
        SchannelSession::CheckAndUpdateCertIfExpiring();

        auto ports = Database::Instance().GetEnabledProxyPorts();
        std::string targetsStr = Database::Instance().GetConfig("health_check_targets", "www.bing.com:443, www.google.com:443");
        
        // 解析目标：支持逗号、分号、换行符分隔
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
        if (targets.empty()) {
            targets = {"www.bing.com:443", "www.google.com:443"};
        }
        
        for (const auto& port : ports) {
            if (!checkerRunning_.load()) break;
            if (port.upstreamType == "auto") {
                std::lock_guard<std::mutex> lock(statusMutex_);
                auto& st = proxyStatus_[port.id];
                st.isAvailable = true;
                st.latency = 1;
                st.failCount = 0;
                continue;
            }
            if (!port.autoCheck) {
                std::lock_guard<std::mutex> lock(statusMutex_);
                auto& st = proxyStatus_[port.id];
                st.isAvailable = true;
                st.failCount = 0;
                continue;
            }

            int latency = -1;
            bool available = CheckProxyConnectivity(port, targets, &latency);

            {
                std::lock_guard<std::mutex> lock(statusMutex_);
                auto& st = proxyStatus_[port.id];
                st.isAvailable = available;
                st.latency = available ? latency : -1;
                if (available) {
                    st.failCount = 0;
                } else {
                    st.failCount++;
                }
            }
        }
        
        // 每一分钟（60秒）执行一次完整检测，或在收到立即检测/终止信号时唤醒
        std::unique_lock<std::mutex> lock(checkerMutex_);
        checkerCv_.wait_for(lock, std::chrono::seconds(60), [this]() {
            return !checkerRunning_.load() || triggerCheck_.exchange(false);
        });
    }
}

bool ProxyServer::CheckProxyConnectivity(const ProxyPort& port, const std::vector<std::string>& targets, int* outLatency) {
    if (port.upstreamType == "auto") {
        if (outLatency) *outLatency = 1;
        return true;
    }

    // 1. 优先对上游物理节点服务器进行轻量非阻塞 TCPing 握手连通性与延时探测
    int tcpLatency = -1;
    bool tcpOk = false;
    if (!port.upstreamHost.empty() && port.upstreamPort > 0) {
        tcpOk = TcpPing(port.upstreamHost, port.upstreamPort, 3000, &tcpLatency);
    }
    
    // 对于非 xray/clash 的常规直连上游节点，若指定了主机端口但 3 秒内完全连不上物理 TCP，判定不可用
    // (xray/clash 包含 CDN/TLS/WebSocket 等复杂封装，物理 TCPing 可能由于无 SNI 阻断，需在步骤2中通过本地 socks 端口实测端到端连通性)
    if (port.upstreamType != "xray" && port.upstreamType != "clash") {
        if (!port.upstreamHost.empty() && port.upstreamPort > 0 && !tcpOk) {
            if (outLatency) *outLatency = -1;
            return false;
        }
    }

    // 2. 如果上游服务器通畅，尝试端到端目标探测获取精确代理应用层延时
    for (const auto& target : targets) {
        if (target.empty()) continue;
        
        std::string host = target;
        int p = 443;
        size_t pos = target.find(':');
        if (pos != std::string::npos) {
            host = target.substr(0, pos);
            p = std::atoi(target.substr(pos + 1).c_str());
        }
        
        auto start = std::chrono::steady_clock::now();
        SOCKET s = INVALID_SOCKET;
        if (port.upstreamType == "socks5") {
            s = ConnectToSocks5(port, host, p);
        } else if (port.upstreamType == "xray") {
            // 通过 xray 本地 SOCKS5 端口检测
            int localPort = XrayManager::Instance().GetLocalSocksPort(port.id);
            if (localPort > 0 && XrayManager::Instance().IsRunning(port.id)) {
                ProxyPort localProxy;
                localProxy.upstreamHost = "127.0.0.1";
                localProxy.upstreamPort = localPort;
                s = ConnectToSocks5(localProxy, host, p);
            }
        } else if (port.upstreamType == "clash") {
            // 通过 clash 本地 SOCKS5 端口检测
            int localPort = ClashManager::Instance().GetLocalSocksPort(port.id);
            if (localPort == 0 || !ClashManager::Instance().IsRunning(port.id)) {
                if (!port.clashConfig.empty()) {
                    localPort = ClashManager::Instance().StartClash(port.id, port.clashConfig);
                }
            }
            if (localPort > 0 && ClashManager::Instance().IsRunning(port.id)) {
                ProxyPort localProxy;
                localProxy.upstreamHost = "127.0.0.1";
                localProxy.upstreamPort = localPort;
                s = ConnectToSocks5(localProxy, host, p);
            }
        } else {
            s = ConnectToHttpProxy(port, host, p);
        }
        
        if (s != INVALID_SOCKET) {
            auto end = std::chrono::steady_clock::now();
            int ms = (int)std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
            closesocket(s);
            if (outLatency) *outLatency = (ms > 0 ? ms : 1);
            return true; // 代理通道验证成功
        }
    }

    // 3. 若目标网站由于境外单次网络过滤受阻，但节点物理服务器 TCPing 确认存活通畅，返回物理延时并判定为节点可用
    if (tcpOk && tcpLatency > 0) {
        if (outLatency) *outLatency = tcpLatency;
        return true;
    }

    if (outLatency) *outLatency = -1;
    return false;
}

SOCKET ProxyServer::ConnectToProxyByType(const ProxyPort& port, const std::string& targetHost, int targetPort) {
    if (port.upstreamType == "clash") {
        return ConnectToClash(port, targetHost, targetPort);
    } else if (port.upstreamType == "xray") {
        return ConnectToXray(port, targetHost, targetPort);
    } else if (port.upstreamType == "socks5") {
        return ConnectToSocks5(port, targetHost, targetPort);
    } else if (port.upstreamType == "http") {
        return ConnectToHttpProxy(port, targetHost, targetPort);
    }
    return INVALID_SOCKET;
}

ProxyServer::ProxyConnResult ProxyServer::ConnectWithFallback(int preferredProxyId, const std::string& targetHost, int targetPort, const std::string& targetGroup) {
    ProxyConnResult result;
    
    // 获取所有已启用的代理端口（按优先级排序）
    auto allPorts = Database::Instance().GetEnabledProxyPorts();
    
    auto isGroupMatch = [](const std::string& nodeGroup, const std::string& reqGroup) -> bool {
        if (nodeGroup == reqGroup) return true;
        if ((reqGroup == "默认" || reqGroup == "默认分组") && 
            (nodeGroup.empty() || nodeGroup == "默认" || nodeGroup == "默认分组")) {
            return true;
        }
        return false;
    };
    
    // 构建候选尝试列表：严格限制在规则指定的目标节点或目标分组内
    std::vector<ProxyPort> tryList;
    
    if (!targetGroup.empty()) {
        // 1. 若同时指定了 preferredProxyId 并且属于该组，优先放首位
        if (preferredProxyId > 0) {
            for (const auto& p : allPorts) {
                if (p.id == preferredProxyId && p.upstreamType != "auto" && isGroupMatch(p.groupName, targetGroup)) {
                    tryList.push_back(p);
                    break;
                }
            }
        }
        
        // 2. 严格按组内优先级顺序添加该分组内的其他节点
        for (const auto& p : allPorts) {
            if (p.id == preferredProxyId && isGroupMatch(p.groupName, targetGroup)) continue;
            if (p.upstreamType == "auto") continue;
            if (isGroupMatch(p.groupName, targetGroup)) {
                tryList.push_back(p);
            }
        }
        
        if (tryList.empty()) {
            Utils::Log("Target group '" + targetGroup + "' has no enabled nodes in policy, skipping fallback");
            return result; // 绝不回退到全量未设定的其他分组节点
        }
    } else if (preferredProxyId > 0) {
        // 仅指定了具体代理节点，严格只尝试该指定节点，绝不尝试策略外节点
        for (const auto& p : allPorts) {
            if (p.id == preferredProxyId && p.upstreamType != "auto") {
                tryList.push_back(p);
                break;
            }
        }
        if (tryList.empty()) {
            Utils::Log("Preferred proxy " + std::to_string(preferredProxyId) + " is not enabled or not found");
            return result;
        }
    } else {
        // preferredProxyId <= 0 且 targetGroup 为空：无有效代理策略
        Utils::Log("ConnectWithFallback: No valid proxy node or group specified");
        return result;
    }
    
    // 尝试连接逻辑：
    // 对于 preferredProxyId（若存在），用户明确指定，无论后台探测状态如何均必须直接尝试实测连接；
    // 对于分组内的候选节点：第一轮优先尝试 IsProxyAvailable 为 true 的节点，若均失败或均被标记不可用，
    // 第二轮再尝试剩余节点（避免后台非阻塞 TCPing 误报或跨国网络瞬时抖动造成整组跳过）。
    
    auto tryConnect = [&](const ProxyPort& p) -> bool {
        // 检查上游容许目标白名单
        if (!p.allowedTargets.empty() && p.allowedTargets != "*") {
            if (!UserManager::IsTargetAllowed(targetHost, targetHost, p.allowedTargets)) {
                Utils::Log("Proxy " + std::to_string(p.id) + " (" + p.description + 
                           ") does not allow target " + targetHost + ", skipping");
                return false;
            }
        }
        
        SOCKET s = ConnectToProxyByType(p, targetHost, targetPort);
        if (s != INVALID_SOCKET) {
            if (preferredProxyId > 0 && p.id != preferredProxyId) {
                Utils::Log("Fallback: using group node " + std::to_string(p.id) + " (" + p.description + 
                           ") instead of " + std::to_string(preferredProxyId));
            }
            result.socket = s;
            result.portId = p.id;
            result.description = p.description;
            return true;
        }
        
        Utils::Log("Failed to connect via proxy " + std::to_string(p.id) + " (" + p.description + 
                    "), trying next...");
        return false;
    };
    
    std::vector<bool> attempted(tryList.size(), false);
    
    // 第一步：如果存在明确的 preferredProxyId，首个节点即为它，优先直接实测连接
    if (preferredProxyId > 0 && !tryList.empty() && tryList[0].id == preferredProxyId) {
        attempted[0] = true;
        if (tryConnect(tryList[0])) {
            return result;
        }
    }
    
    // 第二步：尝试分组内已知可用的节点 (IsProxyAvailable == true)
    for (size_t i = 0; i < tryList.size(); ++i) {
        if (attempted[i]) continue;
        if (!IsProxyAvailable(tryList[i].id)) continue;
        
        attempted[i] = true;
        if (tryConnect(tryList[i])) {
            return result;
        }
    }
    
    // 第三步：若上述均未成功，尝试分组内剩余节点（防止后台探测误判）
    for (size_t i = 0; i < tryList.size(); ++i) {
        if (attempted[i]) continue;
        
        attempted[i] = true;
        if (tryConnect(tryList[i])) {
            return result;
        }
    }
    
    return result;  // socket = INVALID_SOCKET
}
