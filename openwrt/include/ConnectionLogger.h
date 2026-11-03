#pragma once

#include "Common.h"
#include <string>
#include <vector>
#include <mutex>
#include <deque>
#include <fstream>

struct ConnectionLogEntry {
    std::string timestamp;
    std::string username;
    std::string clientIP;
    std::string protocol = "TCP"; // "TCP", "UDP"
    std::string inboundType; // "HTTP", "HTTPS", "SOCKS5", "透明代理"
    std::string targetHost;
    int targetPort;
    std::string action;
    std::string proxyDesc;
};

class ConnectionLogger {
public:
    static ConnectionLogger& Instance();

    void Log(const std::string& username, const std::string& clientIP,
             const std::string& targetHost, int targetPort,
             const std::string& action, const std::string& proxyDesc,
             const std::string& inboundType = "");

    std::vector<ConnectionLogEntry> GetRecentLogs(size_t count = 200);
    void Clear();
    void GetStorageInfo(int64_t& totalBytes, int& recordCount);

private:
    ConnectionLogger();
    ~ConnectionLogger() = default;

    std::mutex mutex_;
    std::deque<ConnectionLogEntry> recentLogs_;
    static constexpr size_t MAX_RECENT_LOGS = 500;
};
