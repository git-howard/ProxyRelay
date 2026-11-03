#pragma once

#include "Common.h"
#include "Database.h"
#include "OpenSSLSession.h"
#include <thread>
#include <map>
#include <vector>
#include <atomic>
#include <mutex>

class ProxyServer {
public:
    static ProxyServer& Instance();

    bool Start();
    void Stop();
    bool IsRunning() const { return running_.load(); }
    int64_t GetStartTime() const { return startTime_.load(); }
    int64_t GetUptime() const {
        if (!running_.load() || startTime_.load() <= 0) return 0;
        int64_t now = (int64_t)time(nullptr);
        return (now >= startTime_.load()) ? (now - startTime_.load()) : 0;
    }

    void ReloadPorts();
    std::vector<int> GetListeningPorts() const;

    struct ProxyConnResult {
        SOCKET socket = INVALID_SOCKET;
        int portId = 0;
        std::string description;
    };

    // 向上游建连（支持单节点、分组智能轮询与故障回退）
    ProxyConnResult ConnectWithFallback(int preferredProxyId, const std::string& targetHost,
                                       int targetPort, const std::string& targetGroup = "",
                                       bool isFallback = false);

    // 双向全双工流式转发
    void RelayData(SOCKET client, SOCKET upstream, int userId, int portId,
                   uint64_t connId = 0, std::shared_ptr<OpenSSLSession> tlsSession = nullptr);

    // 基础连接协议实现
    SOCKET ConnectToUpstream(const ProxyPort& port, const std::string& targetHost, int targetPort);
    SOCKET ConnectDirect(const std::string& targetHost, int targetPort);
    SOCKET ConnectToSocks5(const ProxyPort& port, const std::string& targetHost, int targetPort);
    SOCKET ConnectToHttpProxy(const ProxyPort& port, const std::string& targetHost, int targetPort);
    SOCKET ConnectToClash(const ProxyPort& port, const std::string& targetHost, int targetPort);

    // 代理节点健康检查
    bool CheckProxyConnectivity(const ProxyPort& port, int* outLatency = nullptr);

private:
    ProxyServer() = default;
    ~ProxyServer();

    void ListenerThread(ProxyPort port);
    void HandleClient(SOCKET clientSocket, const std::string& clientAddr, ProxyPort port);

    void HandleHttpProxy(SOCKET clientSocket, const std::string& clientAddr,
                         const ProxyPort& port, int userId, const std::string& username,
                         const std::string& initialRequest, const std::string& extraPayload,
                         std::shared_ptr<OpenSSLSession> tlsSession = nullptr);

    void HandleSocks5Proxy(SOCKET clientSocket, const std::string& clientAddr,
                           const ProxyPort& port, int userId = 0, const std::string& username = "",
                           const std::string& initialData = "",
                           std::shared_ptr<OpenSSLSession> tlsSession = nullptr);

    std::atomic<bool> running_{false};
    std::atomic<int64_t> startTime_{0};
    mutable std::mutex portsMutex_;
    std::map<int, std::thread> listenerThreads_;
    std::map<int, SOCKET> listenSockets_;

    // 自动代理全局监听
    std::thread autoProxyThread_;
    std::atomic<SOCKET> autoProxySocket_{INVALID_SOCKET};
    int currentAutoPort_{0};
};
