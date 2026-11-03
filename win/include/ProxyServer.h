#pragma once

#include "Database.h"
#include <thread>
#include <chrono>
#include <atomic>
#include <vector>
#include <map>
#include <mutex>
#include <condition_variable>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <memory>
#include <algorithm>
#include <cstring>

class SchannelSession;

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
    
    // 重新加载配置
    void ReloadPorts();
    
    // 获取状态
    int GetActiveConnections() const { return activeConnections_.load(); }
    std::vector<int> GetListeningPorts() const;
    
    // 自动代理监听
    void StartAutoProxyListener();
    void StopAutoProxyListener();
    
    // 健康检查
    void StartProxyChecker();
    void StopProxyChecker();
    void TriggerCheck();
    bool IsProxyAvailable(int portId);
    int GetProxyLatency(int portId);
    void UpdateProxyStatus(int portId, bool available, int latency);
    bool CheckProxyConnectivity(const ProxyPort& port, const std::vector<std::string>& targets = {"www.google.com:443", "www.bing.com:443"}, int* outLatency = nullptr);
    
    // 连接指定代理或代理分组，如果不可用则顺序尝试组内或下一优先级代理
    struct ProxyConnResult {
        SOCKET socket = INVALID_SOCKET;
        int portId = 0;
        std::string description;
    };
    ProxyConnResult ConnectWithFallback(int preferredProxyId, const std::string& targetHost, int targetPort, const std::string& targetGroup = "");
    
private:
    ProxyServer() = default;
    ~ProxyServer();
    
    void ListenerThread(ProxyPort port);
    void HandleClient(SOCKET clientSocket, const std::string& clientAddr, ProxyPort port);
    
    void CheckerThread();
    
    // HTTP代理处理
    void HandleHttpProxy(SOCKET clientSocket, const std::string& clientAddr, 
                         const ProxyPort& port, int userId, const std::string& username,
                         const std::string& initialRequest, const std::string& extraPayload,
                         std::shared_ptr<SchannelSession> tlsSession = nullptr);
                         
    // SOCKS5代理处理
    void HandleSocks5Proxy(SOCKET clientSocket, const std::string& clientAddr,
                           const ProxyPort& port, int userId, const std::string& username,
                           const std::string& initialData);
    
    // 连接上游代理
    SOCKET ConnectToUpstream(const ProxyPort& port);
    SOCKET ConnectToSocks5(const ProxyPort& port, const std::string& targetHost, int targetPort);
    SOCKET ConnectToHttpProxy(const ProxyPort& port, const std::string& targetHost, int targetPort);
    SOCKET ConnectToXray(const ProxyPort& port, const std::string& targetHost, int targetPort);
    SOCKET ConnectToClash(const ProxyPort& port, const std::string& targetHost, int targetPort);
    
    // 按代理类型连接（统一入口）
    SOCKET ConnectToProxyByType(const ProxyPort& port, const std::string& targetHost, int targetPort);
    
    // 数据转发（全双工高速流式转发）
    void RelayData(SOCKET client, SOCKET upstream, int userId, int portId, uint64_t connId = 0,
                   std::shared_ptr<SchannelSession> tlsSession = nullptr);
    
    std::atomic<bool> running_{false};
    std::atomic<int64_t> startTime_{0};
    std::atomic<int> activeConnections_{0};
    
    mutable std::mutex portsMutex_;
    std::map<int, std::thread> listenerThreads_;
    std::map<int, SOCKET> listenSockets_;
    
    std::thread autoProxyThread_;
    std::atomic<SOCKET> autoProxySocket_{INVALID_SOCKET};
    
    // 健康检查状态
    struct ProxyStatus {
        bool isAvailable = true;
        int latency = -1; // 毫秒，-1表示未测或不可用
        int failCount = 0;
        std::chrono::steady_clock::time_point nextCheckTime;
    };
    std::map<int, ProxyStatus> proxyStatus_;
    std::mutex statusMutex_;
    std::atomic<bool> checkerRunning_{false};
    std::atomic<bool> triggerCheck_{false};
    std::mutex checkerMutex_;
    std::condition_variable checkerCv_;
    std::thread checkerThread_;
    
    bool wsaInitialized_ = false;
};
