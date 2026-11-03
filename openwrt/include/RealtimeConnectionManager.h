#pragma once

#include "Common.h"
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <chrono>

struct RealtimeConnection {
    uint64_t id = 0;
    std::string timestamp;
    std::string username;
    std::string clientIP;
    std::string protocol = "TCP"; // "TCP", "UDP"
    std::string inboundType = "HTTP"; // "HTTP", "HTTPS", "SOCKS5", "透明代理"
    std::string targetHost;
    int targetPort = 0;
    std::string proxyDesc;
    int64_t uploadBytes = 0;
    int64_t downloadBytes = 0;
    bool active = true;
    SOCKET clientSocket = INVALID_SOCKET;
    SOCKET upstreamSocket = INVALID_SOCKET;
    std::chrono::steady_clock::time_point disconnectTime;
};

class RealtimeConnectionManager {
public:
    static RealtimeConnectionManager& Instance();

    uint64_t AddConnection(const std::string& username, const std::string& clientIP,
                           const std::string& targetHost, int targetPort,
                           const std::string& proxyDesc,
                           SOCKET clientSocket = INVALID_SOCKET,
                           SOCKET upstreamSocket = INVALID_SOCKET,
                           const std::string& inboundType = "HTTP",
                           const std::string& protocol = "TCP");

    void RecordTraffic(uint64_t id, int64_t uploadBytes, int64_t downloadBytes);
    void CloseConnection(uint64_t id);
    bool IsActive(uint64_t id);

    std::vector<RealtimeConnection> GetConnectionsSnapshot();

private:
    RealtimeConnectionManager() = default;
    ~RealtimeConnectionManager() = default;

    std::mutex mutex_;
    uint64_t nextId_ = 1;
    std::map<uint64_t, RealtimeConnection> connections_;
};
