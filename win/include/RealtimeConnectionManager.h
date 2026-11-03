#pragma once

#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <chrono>

struct RealtimeConnection {
    uint64_t id;
    std::string timestamp; // 开始时间
    std::string username;
    std::string clientIP;
    std::string protocol = "TCP"; // "TCP", "UDP"
    std::string inboundType; // "HTTP", "HTTPS", "SOCKS5", "透明代理"
    std::string targetHost;
    int targetPort;
    std::string proxyDesc;
    int64_t uploadBytes;
    int64_t downloadBytes;
    bool active;
    std::chrono::steady_clock::time_point disconnectTime;
};

class RealtimeConnectionManager {
public:
    static RealtimeConnectionManager& Instance();

    uint64_t AddConnection(const std::string& username, const std::string& clientIP,
                           const std::string& targetHost, int targetPort,
                           const std::string& proxyDesc,
                           const std::string& inboundType = "HTTP",
                           const std::string& protocol = "TCP");

    void RecordTraffic(uint64_t id, int64_t uploadBytes, int64_t downloadBytes);

    void CloseConnection(uint64_t id);

    bool IsActive(uint64_t id);

    // 获取所有连接的快照（活跃连接 + 断开10秒内的连接），并清理超期连接
    std::vector<RealtimeConnection> GetConnectionsSnapshot();

private:
    RealtimeConnectionManager() = default;
    ~RealtimeConnectionManager() = default;

    std::mutex mutex_;
    uint64_t nextId_ = 1;
    std::map<uint64_t, RealtimeConnection> connections_;
};
