#include "RealtimeConnectionManager.h"
#include <sstream>
#include <iomanip>
#include <ctime>

RealtimeConnectionManager& RealtimeConnectionManager::Instance() {
    static RealtimeConnectionManager instance;
    return instance;
}

uint64_t RealtimeConnectionManager::AddConnection(const std::string& username, const std::string& clientIP,
                                                  const std::string& targetHost, int targetPort,
                                                  const std::string& proxyDesc,
                                                  const std::string& inboundType,
                                                  const std::string& protocol) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto nowSteady = std::chrono::steady_clock::now();

    // 自动清理断开连接超过10秒的数据，避免未切到实时连接Tab时内存无限增长
    for (auto it = connections_.begin(); it != connections_.end(); ) {
        if (!it->second.active) {
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(nowSteady - it->second.disconnectTime).count();
            if (elapsed >= 10) {
                it = connections_.erase(it);
                continue;
            }
        }
        ++it;
    }

    // 兜底上限：如果总连接数依然过大（如突发高并发），立即清理最早的非活跃连接
    if (connections_.size() > 2000) {
        for (auto it = connections_.begin(); it != connections_.end() && connections_.size() > 1000; ) {
            if (!it->second.active) {
                it = connections_.erase(it);
            } else {
                ++it;
            }
        }
    }

    uint64_t id = nextId_++;

    RealtimeConnection conn;
    conn.id = id;
    
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::tm tm;
    localtime_s(&tm, &time);
    
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    
    conn.timestamp = oss.str();
    conn.username = username;
    conn.clientIP = clientIP;
    conn.protocol = protocol.empty() ? "TCP" : protocol;
    conn.inboundType = inboundType.empty() ? "HTTP" : inboundType;
    conn.targetHost = targetHost;
    conn.targetPort = targetPort;
    conn.proxyDesc = proxyDesc;
    conn.uploadBytes = 0;
    conn.downloadBytes = 0;
    conn.active = true;

    connections_[id] = conn;
    return id;
}

void RealtimeConnectionManager::RecordTraffic(uint64_t id, int64_t uploadBytes, int64_t downloadBytes) {
    if (id == 0) return;
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = connections_.find(id);
    if (it != connections_.end() && it->second.active) {
        it->second.uploadBytes += uploadBytes;
        it->second.downloadBytes += downloadBytes;
    }
}

void RealtimeConnectionManager::CloseConnection(uint64_t id) {
    if (id == 0) return;
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = connections_.find(id);
    if (it != connections_.end() && it->second.active) {
        it->second.active = false;
        it->second.disconnectTime = std::chrono::steady_clock::now();
    }
}

bool RealtimeConnectionManager::IsActive(uint64_t id) {
    if (id == 0) return true;
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = connections_.find(id);
    if (it != connections_.end()) {
        return it->second.active;
    }
    return false;
}

std::vector<RealtimeConnection> RealtimeConnectionManager::GetConnectionsSnapshot() {
    std::lock_guard<std::mutex> lock(mutex_);
    auto now = std::chrono::steady_clock::now();

    // 清理断开连接超过10秒的数据
    for (auto it = connections_.begin(); it != connections_.end(); ) {
        if (!it->second.active) {
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - it->second.disconnectTime).count();
            if (elapsed >= 10) {
                it = connections_.erase(it);
                continue;
            }
        }
        ++it;
    }

    std::vector<RealtimeConnection> snapshot;
    snapshot.reserve(connections_.size());
    // 确保最新建立的连接排在最前面 (最上面)
    for (auto it = connections_.rbegin(); it != connections_.rend(); ++it) {
        snapshot.push_back(it->second);
    }
    return snapshot;
}
