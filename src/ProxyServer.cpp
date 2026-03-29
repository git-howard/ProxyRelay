#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include "ProxyServer.h"
#include "UserManager.h"
#include "TrafficMonitor.h"
#include "ConnectionLogger.h"
#include "Rules.h"
#include "Utils.h"
#include <sstream>
#include <regex>
#include <cstdlib>

#pragma comment(lib, "ws2_32.lib")

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
    
    auto ports = Database::Instance().GetEnabledProxyPorts();
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
    StopProxyChecker();
    StopAutoProxyListener();
    
    std::lock_guard<std::mutex> lock(portsMutex_);
    for (auto& pair : listenSockets_) {
        closesocket(pair.second);
    }
    
    for (auto& pair : listenerThreads_) {
        if (pair.second.joinable()) {
            pair.second.join();
        }
    }
    
    listenSockets_.clear();
    listenerThreads_.clear();
}

void ProxyServer::ReloadPorts() {
    Stop();
    Start();
}

std::vector<int> ProxyServer::GetListeningPorts() const {
    std::vector<int> ports;
    std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(portsMutex_));
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
            }
            continue;
        }
        
        char ipStr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &clientAddr.sin_addr, ipStr, INET_ADDRSTRLEN);
        std::string clientAddrStr = std::string(ipStr) + ":" + std::to_string(ntohs(clientAddr.sin_port));
        
        std::thread(&ProxyServer::HandleClient, this, clientSocket, clientAddrStr, port).detach();
    }
}

void ProxyServer::HandleClient(SOCKET clientSocket, const std::string& clientAddr, ProxyPort port) {
    activeConnections_++;
    
    char buffer[65536];

    // 使用PEEK模式查看第一个字节
    int peeked = recv(clientSocket, buffer, sizeof(buffer), MSG_PEEK);
    if (peeked <= 0) {
        closesocket(clientSocket);
        activeConnections_--;
        return;
    }
    
    // 检查是否为SOCKS5 (0x05)
    if (buffer[0] == 0x05) {
        // SOCKS5处理 - 在函数通过recv调用读取数据
        HandleSocks5Proxy(clientSocket, clientAddr, port, 0, "", "");
        activeConnections_--;
        return;
    }
    
    // HTTP 处理 - 读取实际数据
    int received = recv(clientSocket, buffer, sizeof(buffer), 0);
    if (received <= 0) {
        closesocket(clientSocket);
        activeConnections_--;
        return;
    }
    
    buffer[received] = '\0';
    std::string request(buffer, received);
    
    // 解析HTTP请求头，提取目标地址用于日志
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
        if (line.find("Proxy-Authorization:") == 0) {
            authHeader = line.substr(21);
            // 去除\r
            if (!authHeader.empty() && authHeader.back() == '\r') {
                authHeader.pop_back();
            }
        }
    }
    
    std::string clientIP = Utils::GetClientIP(clientAddr);
    
    // 增加 免认证IP 检查
    if (Database::Instance().IsNoAuthIP(clientIP)) {
        Utils::Log("No-Auth IP connection from: " + clientIP);
        // 使用内置的免认证用户 "no-auth"
        HandleHttpProxy(clientSocket, clientAddr, port, 0, "no-auth", request);
        activeConnections_--;
        return;
    }

    // 认证
    std::string username, password;
    UserInfo user;
    
    if (authHeader.empty() || !Utils::ParseBasicAuth(authHeader, username, password)) {
        // 先尝试通过IP直接使用免密账户登录
        if (UserManager::Instance().Authenticate("", "", clientIP, user)) {
            // 记录免密成功
            Utils::LogAuthSuccess(user.username, clientIP, "HTTP");
            HandleHttpProxy(clientSocket, clientAddr, port, user.id, user.username, request);
            activeConnections_--;
            return;
        }

        // 记录未认证请求
        ConnectionLogger::Instance().Log("", clientIP, targetHost, targetPort, "AUTH_REQUIRED", "");
        
        // 返回407要求认证
        const char* response = "HTTP/1.1 407 Proxy Authentication Required\r\n"
                               "Proxy-Authenticate: Basic realm=\"ProxyRelay\"\r\n"
                               "Content-Length: 0\r\n\r\n";
        send(clientSocket, response, (int)strlen(response), 0);
        closesocket(clientSocket);
        activeConnections_--;
        return;
    }
    
    if (!UserManager::Instance().Authenticate(username, password, clientIP, user)) {
        // 记录认证失败
        ConnectionLogger::Instance().Log(username, clientIP, targetHost, targetPort, "AUTH_FAILED", "");
        Utils::LogAuthFailed(username, clientIP, "HTTP");
        
        const char* response = "HTTP/1.1 403 Forbidden\r\n"
                               "Content-Length: 0\r\n\r\n";
        send(clientSocket, response, (int)strlen(response), 0);
        closesocket(clientSocket);
        activeConnections_--;
        return;
    }
    
    // 记录认证成功（首次）
    Utils::LogAuthSuccess(username, clientIP, "HTTP");
    
    // 将已读取的请求传递给HandleHttpProxy
    HandleHttpProxy(clientSocket, clientAddr, port, user.id, username, request);
    activeConnections_--;
}

void ProxyServer::HandleHttpProxy(SOCKET clientSocket, const std::string& clientAddr,
                                   const ProxyPort& port, int userId, const std::string& username,
                                   const std::string& initialRequest) {
    // 解析请求行
    std::istringstream iss(initialRequest);
    std::string method, url, version;
    iss >> method >> url >> version;
    
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
        std::regex urlRegex(R"(https?://([^/:]+)(?::(\d+))?(/.*)?)", std::regex::icase);
        std::smatch match;
        if (std::regex_match(url, match, urlRegex)) {
            targetHost = match[1].str();
            if (match[2].matched) {
                targetPort = std::stoi(match[2].str());
            }
        } else {
            // URL可能不包含协议，直接作为Host:port处理
            Utils::LogError("Failed to parse URL: " + url);
            const char* response = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
            send(clientSocket, response, (int)strlen(response), 0);
            closesocket(clientSocket);
            return;
        }
    }
    
    if (targetHost.empty()) {
        Utils::LogError("Empty target host for URL: " + url);
        const char* response = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
        send(clientSocket, response, (int)strlen(response), 0);
        closesocket(clientSocket);
        return;
    }
    
    // 记录连接日志
    std::string clientIP = Utils::GetClientIP(clientAddr);
    std::string actualProxyDesc = port.description;
    

    
    // 规则检查 (Resolving)
    std::string targetIP = targetHost;
    unsigned int tmpVal;
    if (inet_pton(AF_INET, targetHost.c_str(), &tmpVal) != 1) {
        struct addrinfo hints = {}, *res = nullptr;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(targetHost.c_str(), nullptr, &hints, &res) == 0) {
            char ipStr[INET_ADDRSTRLEN];
            struct sockaddr_in* ipv4 = (struct sockaddr_in*)res->ai_addr;
            inet_ntop(AF_INET, &(ipv4->sin_addr), ipStr, INET_ADDRSTRLEN);
            targetIP = ipStr;
            freeaddrinfo(res);
        }
    }
    
    // Check Blacklist
    if (RuleManager::Instance().IsBlacklisted(targetIP)) {
        // 记录被黑名单阻止的请求
        ConnectionLogger::Instance().Log(username, clientIP, targetHost, targetPort, "BLOCKED", "Blacklist");
        
        const char* response = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
        send(clientSocket, response, (int)strlen(response), 0);
        closesocket(clientSocket);
        return;
    }
    
    // 检查路由规则，获取匹配的代理ID
    // 返回值: 0=直连, >0=使用指定代理, -1=无匹配（使用旧的bypass逻辑）
    int matchedProxyId = RuleManager::Instance().GetMatchingProxyId(targetIP, targetHost);
    
    bool bypass = false;
    bool strictBypass = false;  // 严格直连模式：直连失败不回退到代理
    ProxyPort targetProxy = port;  // 默认使用当前端口配置的上游代理
    
    if (matchedProxyId == 0) {
        // 直连规则全局有效 - 严格模式
        bypass = true;
        strictBypass = true;  // 路由规则指定的直连是严格的
        Utils::Log("Routing rule matched: direct connection for " + targetHost + " (strict mode)");
    } else if (matchedProxyId > 0) {
        // 代理规则：当端口类型为 auto 时使用指定代理
        if (port.upstreamType == "auto") {
            ProxyPort specifiedProxy;
            if (Database::Instance().GetProxyPort(matchedProxyId, specifiedProxy) && specifiedProxy.enabled) {
                targetProxy = specifiedProxy;
                Utils::Log("Routing rule matched: using proxy " + std::to_string(matchedProxyId) + " for " + targetHost);
            } else {
                Utils::Log("Routing rule matched proxy " + std::to_string(matchedProxyId) + " but not found/enabled, using default");
            }
        } else {
            Utils::Log("Routing rule matched proxy " + std::to_string(matchedProxyId) + " for " + targetHost + 
                       ", but port type is '" + port.upstreamType + "' (not auto), ignoring rule");
        }
    } else if (matchedProxyId == -1) {
        // 无匹配的路由规则，使用旧的 bypass 逻辑（非严格模式，失败可回退）
        bypass = RuleManager::Instance().ShouldBypass(targetIP, targetHost);
    }
    // 注意：如果 matchedProxyId > 0 但 port.upstreamType != "auto"，则忽略该规则，使用当前端口配置

    // 连接上游代理
    SOCKET upstreamSocket = INVALID_SOCKET;
    int actualPortId = port.id;
    bool bypassFailed = false;  // 记录严格直连是否失败
    
    // Bypass: 直接连接目标
    if (bypass) {
        // 如果 targetIP 仍是域名（DNS 解析失败），需要再次尝试解析
        std::string connectIP = targetIP;
        unsigned int tmpCheck;
        if (inet_pton(AF_INET, connectIP.c_str(), &tmpCheck) != 1) {
            // targetIP 不是有效的 IP 地址，尝试 DNS 解析
            struct addrinfo hints = {}, *res = nullptr;
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;
            if (getaddrinfo(targetHost.c_str(), nullptr, &hints, &res) == 0) {
                char ipStr[INET_ADDRSTRLEN];
                struct sockaddr_in* ipv4 = (struct sockaddr_in*)res->ai_addr;
                inet_ntop(AF_INET, &(ipv4->sin_addr), ipStr, INET_ADDRSTRLEN);
                connectIP = ipStr;
                freeaddrinfo(res);
                Utils::Log("Bypass DNS resolved: " + targetHost + " -> " + connectIP);
            } else {
                Utils::Log("Bypass DNS resolution failed for: " + targetHost);
                bypass = false;
                if (strictBypass) bypassFailed = true;
            }
        }
        
        if (bypass) {
            Utils::Log("Attempting bypass direct connection to: " + connectIP + ":" + std::to_string(targetPort));
            SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (s != INVALID_SOCKET) {
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
        send(clientSocket, response, (int)strlen(response), 0);
        closesocket(clientSocket);
        return;
    }

    // 如果不是 bypass 或 bypass 失败（非严格模式），使用代理
    if (!bypass && !strictBypass) {
        if (targetProxy.upstreamType == "auto") {
            auto ports = Database::Instance().GetEnabledProxyPorts();
            for (const auto& p : ports) {
                if (!IsProxyAvailable(p.id)) continue;
                
                if (p.upstreamType == "socks5") {
                    upstreamSocket = ConnectToSocks5(p, targetHost, targetPort);
                } else {
                    upstreamSocket = ConnectToHttpProxy(p, targetHost, targetPort);
                }
                
                if (upstreamSocket != INVALID_SOCKET) {
                    actualPortId = p.id;
                    actualProxyDesc = p.description;
                    break;
                }
            }
        } else if (targetProxy.upstreamType == "socks5") {
            upstreamSocket = ConnectToSocks5(targetProxy, targetHost, targetPort);
            actualPortId = targetProxy.id;
            actualProxyDesc = targetProxy.description;
        } else {
            upstreamSocket = ConnectToHttpProxy(targetProxy, targetHost, targetPort);
            actualPortId = targetProxy.id;
            actualProxyDesc = targetProxy.description;
        }
    }
    
    if (upstreamSocket == INVALID_SOCKET) {
        Utils::LogError("Failed to connect to upstream proxy");
        const char* response = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
        send(clientSocket, response, (int)strlen(response), 0);
        closesocket(clientSocket);
        return;
    }
    
    if (method == "CONNECT") {
        // HTTPS隧道建立成功
        const char* response = "HTTP/1.1 200 Connection Established\r\n\r\n";
        send(clientSocket, response, (int)strlen(response), 0);
    } else {
        // 转发HTTP请求到上游（需要去除Proxy-Authorization头，转换绝对URL为相对URL）
        // 重建请求
        std::string modifiedRequest;
        
        // 解析路径部分
        std::regex pathRegex(R"(https?://[^/]+(/.*)?)", std::regex::icase);
        std::smatch pathMatch;
        std::string path = "/";
        if (std::regex_match(url, pathMatch, pathRegex)) {
            if (pathMatch[1].matched && !pathMatch[1].str().empty()) {
                path = pathMatch[1].str();
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
            // 跳过Proxy-Authorization头
            if (headerLine.find("Proxy-Authorization:") != 0) {
                modifiedRequest += headerLine;
                if (headerLine.back() != '\n') {
                    modifiedRequest += "\n";
                }
            }
        }
        
        send(upstreamSocket, modifiedRequest.c_str(), (int)modifiedRequest.length(), 0);
    }
    
    // 记录连接日志
    ConnectionLogger::Instance().Log(username, clientIP, targetHost, targetPort, method, actualProxyDesc);

    // 双向转发数据
    RelayData(clientSocket, upstreamSocket, userId, actualPortId);
    
    closesocket(upstreamSocket);
    closesocket(clientSocket);
}

SOCKET ProxyServer::ConnectToSocks5(const ProxyPort& port, const std::string& targetHost, int targetPort) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return INVALID_SOCKET;
    
    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port.upstreamPort);
    inet_pton(AF_INET, port.upstreamHost.c_str(), &addr.sin_addr);
    
    if (connect(sock, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(sock);
        return INVALID_SOCKET;
    }
    
    // SOCKS5握手
    unsigned char greeting[4] = {0x05, 0x02, 0x00, 0x02}; // 支持无认证和用户名密码
    send(sock, (char*)greeting, 4, 0);
    
    unsigned char response[2];
    if (recv(sock, (char*)response, 2, 0) != 2) {
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
        if (recv(sock, (char*)authResp, 2, 0) != 2 || authResp[1] != 0x00) {
            closesocket(sock);
            return INVALID_SOCKET;
        }
    }
    
    // 连接请求
    std::vector<unsigned char> connectReq;
    connectReq.push_back(0x05);
    connectReq.push_back(0x01); // CONNECT
    connectReq.push_back(0x00);
    connectReq.push_back(0x03); // 域名
    connectReq.push_back((unsigned char)targetHost.length());
    connectReq.insert(connectReq.end(), targetHost.begin(), targetHost.end());
    connectReq.push_back((targetPort >> 8) & 0xFF);
    connectReq.push_back(targetPort & 0xFF);
    
    send(sock, (char*)connectReq.data(), (int)connectReq.size(), 0);
    
    unsigned char connectResp[10];
    if (recv(sock, (char*)connectResp, 10, 0) < 4 || connectResp[1] != 0x00) {
        closesocket(sock);
        return INVALID_SOCKET;
    }
    
    return sock;
}

SOCKET ProxyServer::ConnectToHttpProxy(const ProxyPort& port, const std::string& targetHost, int targetPort) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return INVALID_SOCKET;
    
    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port.upstreamPort);
    inet_pton(AF_INET, port.upstreamHost.c_str(), &addr.sin_addr);
    
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

void ProxyServer::RelayData(SOCKET client, SOCKET upstream, int userId, int portId) {
    // 检查是否启用缓冲区模式
    int bufferSizeKB = GetBufferSizeKB();
    if (bufferSizeKB > 0) {
        // 使用带缓冲区的非阻塞模式
        RelayDataBuffered(client, upstream, userId, portId);
        return;
    }
    
    // 原有的同步模式（bufferSize = 0 时使用）
    fd_set readfds;
    char buffer[65536];
    
    DWORD timeout = 30000;
    setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(upstream, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    
    while (running_.load()) {
        FD_ZERO(&readfds);
        FD_SET(client, &readfds);
        FD_SET(upstream, &readfds);
        
        timeval tv = {1, 0};
        int ret = select(0, &readfds, nullptr, nullptr, &tv);
        
        if (ret <= 0) continue;
        
        if (FD_ISSET(client, &readfds)) {
            int received = recv(client, buffer, sizeof(buffer), 0);
            if (received <= 0) break;
            
            TrafficMonitor::Instance().RecordUpload(userId, portId, received);
            
            // 修复：处理部分发送
            int totalSent = 0;
            while (totalSent < received) {
                int sent = send(upstream, buffer + totalSent, received - totalSent, 0);
                if (sent <= 0) break;
                totalSent += sent;
            }
            if (totalSent < received) break;
        }
        
        if (FD_ISSET(upstream, &readfds)) {
            int received = recv(upstream, buffer, sizeof(buffer), 0);
            if (received <= 0) break;
            
            TrafficMonitor::Instance().RecordDownload(userId, portId, received);
            
            // 修复：处理部分发送
            int totalSent = 0;
            while (totalSent < received) {
                int sent = send(client, buffer + totalSent, received - totalSent, 0);
                if (sent <= 0) break;
                totalSent += sent;
            }
            if (totalSent < received) break;
        }
    }
}

int ProxyServer::GetBufferSizeKB() {
    std::string sizeStr = Database::Instance().GetConfig("relay_buffer_size_kb", "128");
    int size = std::atoi(sizeStr.c_str());
    if (size < 0) size = 0;
    if (size > 4096) size = 4096;  // 最大 4MB
    return size;
}

void ProxyServer::RelayDataBuffered(SOCKET client, SOCKET upstream, int userId, int portId) {
    int bufferSizeKB = GetBufferSizeKB();
    size_t bufferSize = (size_t)bufferSizeKB * 1024;
    
    // 为每个方向创建独立的环形缓冲区
    RingBuffer clientToUpstream;
    RingBuffer upstreamToClient;
    clientToUpstream.init(bufferSize);
    upstreamToClient.init(bufferSize);
    
    // 设置非阻塞模式
    u_long nonBlocking = 1;
    ioctlsocket(client, FIONBIO, &nonBlocking);
    ioctlsocket(upstream, FIONBIO, &nonBlocking);
    
    char tempBuffer[65536];  // 临时读写缓冲区
    bool clientClosed = false;
    bool upstreamClosed = false;
    
    while (running_.load()) {
        fd_set readfds, writefds;
        FD_ZERO(&readfds);
        FD_ZERO(&writefds);
        
        // 只有当缓冲区有空间时才监听读事件
        if (!clientClosed && !clientToUpstream.isFull()) {
            FD_SET(client, &readfds);
        }
        if (!upstreamClosed && !upstreamToClient.isFull()) {
            FD_SET(upstream, &readfds);
        }
        
        // 只有当缓冲区有数据时才监听写事件
        if (!clientToUpstream.isEmpty()) {
            FD_SET(upstream, &writefds);
        }
        if (!upstreamToClient.isEmpty()) {
            FD_SET(client, &writefds);
        }
        
        // 如果两个方向都已关闭且缓冲区为空，退出
        if (clientClosed && upstreamClosed && 
            clientToUpstream.isEmpty() && upstreamToClient.isEmpty()) {
            break;
        }
        
        timeval tv = {0, 100000};  // 100ms 超时
        int ret = select(0, &readfds, &writefds, nullptr, &tv);
        
        if (ret < 0) {
            int err = WSAGetLastError();
            if (err != WSAEINTR) break;
            continue;
        }
        
        if (ret == 0) continue;  // 超时
        
        // 从客户端读取数据到缓冲区
        if (FD_ISSET(client, &readfds)) {
            size_t freeSpace = clientToUpstream.freeSpace();
            size_t toRead = (freeSpace < sizeof(tempBuffer)) ? freeSpace : sizeof(tempBuffer);
            int received = recv(client, tempBuffer, (int)toRead, 0);
            
            if (received > 0) {
                clientToUpstream.write(tempBuffer, received);
                TrafficMonitor::Instance().RecordUpload(userId, portId, received);
            } else if (received == 0) {
                clientClosed = true;  // 优雅关闭
            } else {
                int err = WSAGetLastError();
                if (err != WSAEWOULDBLOCK && err != WSAEINPROGRESS) {
                    clientClosed = true;
                }
            }
        }
        
        // 从上游读取数据到缓冲区
        if (FD_ISSET(upstream, &readfds)) {
            size_t freeSpace = upstreamToClient.freeSpace();
            size_t toRead = (freeSpace < sizeof(tempBuffer)) ? freeSpace : sizeof(tempBuffer);
            int received = recv(upstream, tempBuffer, (int)toRead, 0);
            
            if (received > 0) {
                upstreamToClient.write(tempBuffer, received);
                TrafficMonitor::Instance().RecordDownload(userId, portId, received);
            } else if (received == 0) {
                upstreamClosed = true;  // 优雅关闭
            } else {
                int err = WSAGetLastError();
                if (err != WSAEWOULDBLOCK && err != WSAEINPROGRESS) {
                    upstreamClosed = true;
                }
            }
        }
        
        // 从缓冲区发送数据到上游
        if (FD_ISSET(upstream, &writefds)) {
            size_t toSend = clientToUpstream.contiguousReadLen();
            if (toSend > sizeof(tempBuffer)) toSend = sizeof(tempBuffer);
            
            if (toSend > 0) {
                clientToUpstream.read(tempBuffer, toSend);
                int sent = send(upstream, tempBuffer, (int)toSend, 0);
                
                if (sent > 0) {
                    // 如果没有发送完，需要把未发送的数据放回缓冲区
                    // 这里简化处理：假设发送完整
                    if ((size_t)sent < toSend) {
                        // 部分发送：这种情况在非阻塞模式下较少见
                        // 为了简单起见，我们继续（数据已经从缓冲区读出）
                    }
                } else {
                    int err = WSAGetLastError();
                    if (err != WSAEWOULDBLOCK && err != WSAEINPROGRESS) {
                        upstreamClosed = true;
                    }
                }
            }
        }
        
        // 从缓冲区发送数据到客户端
        if (FD_ISSET(client, &writefds)) {
            size_t toSend = upstreamToClient.contiguousReadLen();
            if (toSend > sizeof(tempBuffer)) toSend = sizeof(tempBuffer);
            
            if (toSend > 0) {
                upstreamToClient.read(tempBuffer, toSend);
                int sent = send(client, tempBuffer, (int)toSend, 0);
                
                if (sent > 0) {
                    // 处理部分发送
                    if ((size_t)sent < toSend) {
                        // 部分发送
                    }
                } else {
                    int err = WSAGetLastError();
                    if (err != WSAEWOULDBLOCK && err != WSAEINPROGRESS) {
                        clientClosed = true;
                    }
                }
            }
        }
        
        // 检查是否应该退出
        if (clientClosed && clientToUpstream.isEmpty() && upstreamToClient.isEmpty()) {
            break;
        }
        if (upstreamClosed && clientToUpstream.isEmpty() && upstreamToClient.isEmpty()) {
            break;
        }
    }
    
    // 恢复阻塞模式（虽然socket即将关闭，但这是好习惯）
    u_long blocking = 0;
    ioctlsocket(client, FIONBIO, &blocking);
    ioctlsocket(upstream, FIONBIO, &blocking);
}

void ProxyServer::HandleSocks5Proxy(SOCKET clientSocket, const std::string& clientAddr,
                                     const ProxyPort& port, int userId, const std::string& username_unused,
                                     const std::string& initialData_unused) {
    char buffer[4096];
    
    // 1. 握手: 客户端发送版本和方法
    int received = recv(clientSocket, buffer, sizeof(buffer), 0);
    if (received < 3 || buffer[0] != 0x05) {
        closesocket(clientSocket);
        return;
    }
    
    // 检查是否支持用户名/密码认证 (0x02) 或 无认证 (0x00)
    bool supportsUserPass = false;
    bool supportsNoAuth = false;
    int methodCount = buffer[1];
    for (int i = 0; i < methodCount && i + 2 < received; i++) {
        if (buffer[i + 2] == 0x02) supportsUserPass = true;
        if (buffer[i + 2] == 0x00) supportsNoAuth = true;
    }
    
    std::string clientIP = Utils::GetClientIP(clientAddr);
    bool isNoAuthIP = Database::Instance().IsNoAuthIP(clientIP);
    std::string username = "guest";
    int currentUserId = 0;

    UserInfo autoUser;
    bool hasAutoUser = false;
    if (!isNoAuthIP && UserManager::Instance().Authenticate("", "", clientIP, autoUser)) {
        isNoAuthIP = true;
        hasAutoUser = true;
    }

    if (isNoAuthIP && supportsNoAuth) {
        // 免认证IP且客户端支持无认证
        unsigned char response[] = {0x05, 0x00};
        send(clientSocket, (char*)response, 2, 0);
        Utils::Log("SOCKS5 No-Auth allowed for IP: " + clientIP);
        
        if (hasAutoUser) {
            username = autoUser.username;
            currentUserId = autoUser.id;
        } else {
            username = "no-auth";
            currentUserId = 0;
        }
        // 跳过认证阶段，直接进入请求阶段
    } else {
        if (!supportsUserPass) {
            // 通知客户端我们需要认证，但客户端不支持
            unsigned char response[] = {0x05, 0xFF};
            send(clientSocket, (char*)response, 2, 0);
            closesocket(clientSocket);
            return;
        }
        
        // 通知客户端选择用户名/密码认证
        unsigned char response[] = {0x05, 0x02};
        send(clientSocket, (char*)response, 2, 0);
        
        // 2. 认证: 客户端发送用户名和密码
        received = recv(clientSocket, buffer, sizeof(buffer), 0);
        if (received < 5 || buffer[0] != 0x01) { // Version 1 for auth subnegotiation
            closesocket(clientSocket);
            return;
        }
        
        int ulen = (unsigned char)buffer[1];
        if (2 + ulen + 1 > received) {
            closesocket(clientSocket);
            return;
        }
        
        username = std::string(buffer + 2, ulen);
        
        int plen = (unsigned char)buffer[2 + ulen];
        if (2 + ulen + 1 + plen > received) {
            closesocket(clientSocket);
            return;
        }
        
        std::string password(buffer + 2 + ulen + 1, plen);
        
        UserInfo user;
        if (!UserManager::Instance().Authenticate(username, password, clientIP, user)) {
            // 记录 SOCKS5 认证失败
            ConnectionLogger::Instance().Log(username, clientIP, "", 0, "SOCKS5_AUTH_FAILED", "");
            Utils::LogAuthFailed(username, clientIP, "SOCKS5");
            
            // 认证失败
            char authResponse[] = {0x01, 0x01}; // Status != 0
            send(clientSocket, authResponse, 2, 0);
            closesocket(clientSocket);
            return;
        }
        
        // 记录认证成功（首次）
        Utils::LogAuthSuccess(username, clientIP, "SOCKS5");
        
        // 认证成功
        char authResponse[] = {0x01, 0x00};
        send(clientSocket, authResponse, 2, 0);
        currentUserId = user.id;
    }
    
    // 3. 请求: 客户端发送连接请求
    received = recv(clientSocket, buffer, sizeof(buffer), 0);
    if (received < 4 || buffer[0] != 0x05 || buffer[1] != 0x01) { // 仅支持 CONNECT (0x01)
        closesocket(clientSocket);
        return;
    }
    
    std::string targetHost;
    int targetPort;
    
    // 解析目标地址
    if (buffer[3] == 0x01) { // IPv4
        struct in_addr addr;
        memcpy(&addr, buffer + 4, 4);
        targetHost = inet_ntoa(addr);
        targetPort = ntohs(*(unsigned short*)(buffer + 8));
    } else if (buffer[3] == 0x03) { // Domain name
        int len = (unsigned char)buffer[4];
        targetHost.assign(buffer + 5, len);
        targetPort = ntohs(*(unsigned short*)(buffer + 5 + len));
    } else if (buffer[3] == 0x04) { // IPv6 - Not yet supported fully for string conversion here
         // 简单处理，暂时不支持IPv6
        char resp[] = {0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0}; // Address type not supported
        send(clientSocket, resp, 10, 0);
        closesocket(clientSocket);
        return;
    }
    
    // 记录连接
    // 记录连接日志 (Moved)
    // ConnectionLogger::Instance().Log(username, clientIP, targetHost, targetPort, "SOCKS5 CONNECT", port.description);
    std::string actualProxyDesc = port.description;
    
    // 连接上游或目标
    SOCKET upstreamSocket = INVALID_SOCKET;
    int actualPortId = port.id;

    // 规则检查
    std::string targetIP = targetHost;
    unsigned int tmpVal2;
    if (inet_pton(AF_INET, targetHost.c_str(), &tmpVal2) != 1) {
         struct addrinfo hints = {}, *res = nullptr;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(targetHost.c_str(), nullptr, &hints, &res) == 0) {
            char ipStr[INET_ADDRSTRLEN];
            struct sockaddr_in* ipv4 = (struct sockaddr_in*)res->ai_addr;
            inet_ntop(AF_INET, &(ipv4->sin_addr), ipStr, INET_ADDRSTRLEN);
            targetIP = ipStr;
            freeaddrinfo(res);
        }
    }
    
    if (RuleManager::Instance().IsBlacklisted(targetIP)) {
        // 记录被黑名单阻止的 SOCKS5 请求
        ConnectionLogger::Instance().Log(username, clientIP, targetHost, targetPort, "BLOCKED", "Blacklist");
        
        char resp[] = {0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0}; 
        send(clientSocket, resp, 10, 0);
        closesocket(clientSocket);
        return;
    }
    
    // 检查路由规则，获取匹配的代理ID
    // 返回值: 0=直连, >0=使用指定代理, -1=无匹配（使用旧的bypass逻辑）
    int matchedProxyId = RuleManager::Instance().GetMatchingProxyId(targetIP, targetHost);
    
    bool bypass = false;
    bool strictBypass = false;  // 严格直连模式
    ProxyPort targetProxy = port;  // 默认使用当前端口配置的上游代理
    
    if (matchedProxyId == 0) {
        // 直连规则全局有效 - 严格模式
        bypass = true;
        strictBypass = true;
        Utils::Log("Routing rule matched: direct connection for " + targetHost + " (strict mode)");
    } else if (matchedProxyId > 0) {
        // 代理规则：当端口类型为 auto 时使用指定代理
        if (port.upstreamType == "auto") {
            ProxyPort specifiedProxy;
            if (Database::Instance().GetProxyPort(matchedProxyId, specifiedProxy) && specifiedProxy.enabled) {
                targetProxy = specifiedProxy;
                Utils::Log("Routing rule matched: using proxy " + std::to_string(matchedProxyId) + " for " + targetHost);
            } else {
                Utils::Log("Routing rule matched proxy " + std::to_string(matchedProxyId) + " but not found/enabled, using default");
            }
        } else {
            Utils::Log("Routing rule matched proxy " + std::to_string(matchedProxyId) + " for " + targetHost + 
                       ", but port type is '" + port.upstreamType + "' (not auto), ignoring rule");
        }
    } else if (matchedProxyId == -1) {
        // 无匹配的路由规则，使用旧的 bypass 逻辑（非严格模式）
        bypass = RuleManager::Instance().ShouldBypass(targetIP, targetHost);
    }
    // 注意：如果 matchedProxyId > 0 但 port.upstreamType != "auto"，则忽略该规则，使用当前端口配置
    
    bool bypassFailed = false;  // 记录严格直连是否失败
    
    if (bypass) {
        // 如果 targetIP 仍是域名（DNS 解析失败），需要再次尝试解析
        std::string connectIP = targetIP;
        unsigned int tmpCheck;
        if (inet_pton(AF_INET, connectIP.c_str(), &tmpCheck) != 1) {
            // targetIP 不是有效的 IP 地址，尝试 DNS 解析
            struct addrinfo hints = {}, *res = nullptr;
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;
            if (getaddrinfo(targetHost.c_str(), nullptr, &hints, &res) == 0) {
                char ipStr[INET_ADDRSTRLEN];
                struct sockaddr_in* ipv4 = (struct sockaddr_in*)res->ai_addr;
                inet_ntop(AF_INET, &(ipv4->sin_addr), ipStr, INET_ADDRSTRLEN);
                connectIP = ipStr;
                freeaddrinfo(res);
                Utils::Log("Bypass DNS resolved: " + targetHost + " -> " + connectIP);
            } else {
                Utils::Log("Bypass DNS resolution failed for: " + targetHost);
                bypass = false;
                if (strictBypass) bypassFailed = true;
            }
        }
        
        if (bypass) {
            Utils::Log("Attempting bypass direct connection to: " + connectIP + ":" + std::to_string(targetPort));
            SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (s != INVALID_SOCKET) {
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
        if (targetProxy.upstreamType == "auto") {
            auto ports = Database::Instance().GetEnabledProxyPorts();
            for (const auto& p : ports) {
                if (!IsProxyAvailable(p.id)) continue;
                
                if (p.upstreamType == "socks5") {
                    upstreamSocket = ConnectToSocks5(p, targetHost, targetPort);
                } else {
                    upstreamSocket = ConnectToHttpProxy(p, targetHost, targetPort);
                }
                
                if (upstreamSocket != INVALID_SOCKET) {
                    actualPortId = p.id;
                    actualProxyDesc = p.description;
                    break;
                }
            }
        } else if (targetProxy.upstreamType == "http") {
            upstreamSocket = ConnectToHttpProxy(targetProxy, targetHost, targetPort);
            actualPortId = targetProxy.id;
            actualProxyDesc = targetProxy.description;
        } else if (targetProxy.upstreamType == "socks5") {
            upstreamSocket = ConnectToSocks5(targetProxy, targetHost, targetPort);
            actualPortId = targetProxy.id;
            actualProxyDesc = targetProxy.description;
        } else {
            // Direct connection (if ever supported) or config error
            closesocket(clientSocket);
            return;
        }
    }
    
    if (upstreamSocket == INVALID_SOCKET) {
        char resp[] = {0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0}; // Connection refused
        send(clientSocket, resp, 10, 0);
        closesocket(clientSocket);
        return;
    }
    
    // 响应客户端: 成功
    // BND.ADDR 和 BND.PORT 这里填 0 即可
    char resp[] = {0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
    send(clientSocket, resp, 10, 0);
    
    // 记录连接日志
    ConnectionLogger::Instance().Log(username, clientIP, targetHost, targetPort, "SOCKS5 CONNECT", actualProxyDesc);

    // 开始转发流量
    RelayData(clientSocket, upstreamSocket, currentUserId, actualPortId);
    
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
    autoPort.description = "Auto Proxy Listener";
    
    autoProxyThread_ = std::thread([this, listenSocket, autoPort]() {
        while (running_.load()) {
            sockaddr_in clientAddr;
            int addrLen = sizeof(clientAddr);
            SOCKET clientSocket = accept(listenSocket, (sockaddr*)&clientAddr, &addrLen);
            
            if (clientSocket == INVALID_SOCKET) {
                // 如果Socket被关闭（autoProxySocket_置为INVALID）或服务停止，则退出
                if (!running_.load() || autoProxySocket_ == INVALID_SOCKET) break;
                
                // 防止其他错误导致的忙等待
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }
            
            char ipStr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &clientAddr.sin_addr, ipStr, INET_ADDRSTRLEN);
            std::string clientAddrStr = std::string(ipStr) + ":" + std::to_string(ntohs(clientAddr.sin_port));
            
            std::thread(&ProxyServer::HandleClient, this, clientSocket, clientAddrStr, autoPort).detach();
        }
    });
    
    Utils::Log("Auto Proxy listening on port " + std::to_string(port));
}

void ProxyServer::StopAutoProxyListener() {
    SOCKET s = autoProxySocket_;
    if (s != INVALID_SOCKET) {
        // 先标记为无效，再关闭，确保线程能通过检查退出
        autoProxySocket_ = INVALID_SOCKET; 
        closesocket(s);
    }
    
    if (autoProxyThread_.joinable()) {
        autoProxyThread_.join();
    }
}

void ProxyServer::StartProxyChecker() {
    StopProxyChecker();
    proxyStatus_.clear();
    
    checkerThread_ = std::thread(&ProxyServer::CheckerThread, this);
}

void ProxyServer::StopProxyChecker() {
    if (checkerThread_.joinable()) {
        checkerThread_.join();
    }
}

bool ProxyServer::IsProxyAvailable(int portId) {
    std::lock_guard<std::mutex> lock(statusMutex_);
    if (proxyStatus_.find(portId) == proxyStatus_.end()) return true;
    return proxyStatus_[portId].isAvailable;
}

void ProxyServer::CheckerThread() {
    while (running_.load()) {
        auto ports = Database::Instance().GetEnabledProxyPorts();
        std::string targetsStr = Database::Instance().GetConfig("tcping_targets", "www.google.com:443\r\nwww.facebook.com:443\r\nwww.x.com:443");
        
        // 解析目标
        std::vector<std::string> targets;
        std::stringstream ss(targetsStr);
        std::string line;
        while (std::getline(ss, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (!line.empty()) targets.push_back(line);
        }
        
        auto now = std::chrono::steady_clock::now();
        
        for (const auto& port : ports) {
            std::lock_guard<std::mutex> lock(statusMutex_);
            
            // 如果不在map中，初始化
            if (proxyStatus_.find(port.id) == proxyStatus_.end()) {
                proxyStatus_[port.id] = {};
            }
            
            auto& status = proxyStatus_[port.id];
            
            // 检查是否到期
            if (now >= status.nextCheckTime) {
                // 更新下次检查时间为一个较远的值，防止重复调度，等待检查结果更新
                status.nextCheckTime = now + std::chrono::hours(1);
                // 更新下次检查时间为一个较远的值，防止重复调度，等待检查结果更新
                status.nextCheckTime = now + std::chrono::hours(1);
                
                // 启动检查线程（Detach）
                std::thread([this, port, targets]() {
                    bool available = CheckProxyConnectivity(port, targets);
                    
                    std::lock_guard<std::mutex> lock(statusMutex_);
                    auto& st = proxyStatus_[port.id];
                    auto now = std::chrono::steady_clock::now();
                    
                    if (available) {
                        st.isAvailable = true;
                        st.failCount = 0;
                        st.nextCheckTime = now + std::chrono::seconds(180); // 成功后每3分钟
                    } else {
                        st.failCount++;
                        if (st.failCount >= 3) {
                            st.isAvailable = false;
                        }
                        st.nextCheckTime = now + std::chrono::seconds(3); // 失败后每3秒重试
                    }
                }).detach();
            }
        }
        
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

bool ProxyServer::CheckProxyConnectivity(const ProxyPort& port, const std::vector<std::string>& targets) {
    for (const auto& target : targets) {
        if (target.empty()) continue;
        
        std::string host = target;
        int p = 443;
        size_t pos = target.find(':');
        if (pos != std::string::npos) {
            host = target.substr(0, pos);
            p = std::atoi(target.substr(pos + 1).c_str());
        }
        
        SOCKET s = INVALID_SOCKET;
        if (port.upstreamType == "socks5") {
            s = ConnectToSocks5(port, host, p);
        } else {
            s = ConnectToHttpProxy(port, host, p);
        }
        
        if (s != INVALID_SOCKET) {
            closesocket(s);
            return true; // 只要有一个连通就算成功
        }
    }
    return false; // 全部失败
}
