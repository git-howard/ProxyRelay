#include "RealtimeConnectionManager.h"
#include "Utils.h"

RealtimeConnectionManager& RealtimeConnectionManager::Instance() {
    static RealtimeConnectionManager instance;
    return instance;
}

uint64_t RealtimeConnectionManager::AddConnection(const std::string& username, const std::string& clientIP,
                                                 const std::string& targetHost, int targetPort,
                                                 const std::string& proxyDesc,
                                                 SOCKET clientSocket, SOCKET upstreamSocket,
                                                 const std::string& inboundType,
                                                 const std::string& protocol) {
    std::lock_guard<std::mutex> lock(mutex_);
    uint64_t id = nextId_++;

    RealtimeConnection conn;
    conn.id = id;
    conn.timestamp = Utils::GetCurrentDateTime();
    conn.username = username.empty() ? "anonymous" : username;
    conn.clientIP = clientIP;
    conn.protocol = protocol.empty() ? "TCP" : protocol;
    conn.inboundType = inboundType.empty() ? "HTTP" : inboundType;
    conn.targetHost = targetHost;
    conn.targetPort = targetPort;
    conn.proxyDesc = proxyDesc;
    conn.active = true;
    conn.clientSocket = clientSocket;
    conn.upstreamSocket = upstreamSocket;

    connections_[id] = conn;
    return id;
}

void RealtimeConnectionManager::RecordTraffic(uint64_t id, int64_t uploadBytes, int64_t downloadBytes) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = connections_.find(id);
    if (it != connections_.end()) {
        it->second.uploadBytes += uploadBytes;
        it->second.downloadBytes += downloadBytes;
    }
}

void RealtimeConnectionManager::CloseConnection(uint64_t id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = connections_.find(id);
    if (it != connections_.end()) {
        if (it->second.active) {
            it->second.active = false;
            it->second.disconnectTime = std::chrono::steady_clock::now();
            if (it->second.clientSocket != INVALID_SOCKET) {
                shutdown(it->second.clientSocket, SHUT_RDWR);
                closesocket(it->second.clientSocket);
                it->second.clientSocket = INVALID_SOCKET;
            }
            if (it->second.upstreamSocket != INVALID_SOCKET) {
                shutdown(it->second.upstreamSocket, SHUT_RDWR);
                closesocket(it->second.upstreamSocket);
                it->second.upstreamSocket = INVALID_SOCKET;
            }
        }
    }
}

bool RealtimeConnectionManager::IsActive(uint64_t id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = connections_.find(id);
    return (it != connections_.end() && it->second.active);
}

std::vector<RealtimeConnection> RealtimeConnectionManager::GetConnectionsSnapshot() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<RealtimeConnection> list;
    auto now = std::chrono::steady_clock::now();

    for (auto it = connections_.begin(); it != connections_.end();) {
        if (!it->second.active) {
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - it->second.disconnectTime).count();
            if (elapsed > 10) { // 断开超过10秒后清理
                it = connections_.erase(it);
                continue;
            }
        }
        list.push_back(it->second);
        ++it;
    }
    // 确保最新建立的连接排在最前面 (最上面)
    std::reverse(list.begin(), list.end());
    return list;
}
