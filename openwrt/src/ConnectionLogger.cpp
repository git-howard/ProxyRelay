#include "ConnectionLogger.h"
#include "Utils.h"
#include <algorithm>

ConnectionLogger& ConnectionLogger::Instance() {
    static ConnectionLogger instance;
    return instance;
}

ConnectionLogger::ConnectionLogger() = default;

void ConnectionLogger::Log(const std::string& username, const std::string& clientIP,
                           const std::string& targetHost, int targetPort,
                           const std::string& action, const std::string& proxyDesc,
                           const std::string& inboundType) {
    std::string actualType = inboundType;
    if (actualType.empty()) {
        if (action.find("TPROXY") != std::string::npos) {
            actualType = "透明代理";
        } else if (action.find("SOCKS5") != std::string::npos) {
            actualType = "SOCKS5";
        } else if (action == "CONNECT" || targetPort == 443) {
            actualType = "HTTPS";
        } else {
            actualType = "HTTP";
        }
    }

    std::string proto = "TCP";
    if (action.find("UDP") != std::string::npos || inboundType.find("UDP") != std::string::npos) {
        proto = "UDP";
    }

    ConnectionLogEntry entry{
        Utils::GetCurrentDateTime(),
        username.empty() ? "anonymous" : username,
        clientIP,
        proto,
        actualType,
        targetHost,
        targetPort,
        action,
        proxyDesc
    };

    std::lock_guard<std::mutex> lock(mutex_);
    recentLogs_.push_front(std::move(entry));
    if (recentLogs_.size() > MAX_RECENT_LOGS) {
        recentLogs_.pop_back();
    }
}

std::vector<ConnectionLogEntry> ConnectionLogger::GetRecentLogs(size_t count) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<ConnectionLogEntry> res;
    size_t n = std::min(count, recentLogs_.size());
    res.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        res.push_back(recentLogs_[i]);
    }
    return res;
}

void ConnectionLogger::Clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    recentLogs_.clear();
}

void ConnectionLogger::GetStorageInfo(int64_t& totalBytes, int& recordCount) {
    std::lock_guard<std::mutex> lock(mutex_);
    recordCount = (int)recentLogs_.size();
    totalBytes = 0;
    for (const auto& l : recentLogs_) {
        totalBytes += (int64_t)(l.timestamp.size() + l.username.size() + l.clientIP.size() +
                                l.protocol.size() + l.inboundType.size() + l.targetHost.size() +
                                l.action.size() + l.proxyDesc.size() + 48);
    }
}
