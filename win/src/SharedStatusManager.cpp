#include "SharedStatusManager.h"
#include "ProxyServer.h"
#include <sddl.h>
#include <algorithm>
#include <cstring>

static const wchar_t* SHARED_MEM_GLOBAL   = L"Global\\ProxyRelay_Service_SharedStatus";
static const wchar_t* SHARED_MEM_LOCAL    = L"Local\\ProxyRelay_Service_SharedStatus";
static const wchar_t* SHARED_EVENT_GLOBAL = L"Global\\ProxyRelay_Service_ReloadEvent";
static const wchar_t* SHARED_EVENT_LOCAL  = L"Local\\ProxyRelay_Service_ReloadEvent";
static const uint32_t SHARED_MAGIC         = 0x5052454C; // 'PREL'

static void SafeCopyStr(char* dest, size_t destSize, const std::string& src) {
    if (!dest || destSize == 0) return;
    size_t copyLen = (std::min)(src.length(), destSize - 1);
    std::memcpy(dest, src.data(), copyLen);
    dest[copyLen] = '\0';
}

SharedStatusManager& SharedStatusManager::Instance() {
    static SharedStatusManager instance;
    return instance;
}

SharedStatusManager::SharedStatusManager() = default;

SharedStatusManager::~SharedStatusManager() {
    Close();
}

void SharedStatusManager::Close() {
    if (pSharedData_) {
        UnmapViewOfFile(pSharedData_);
        pSharedData_ = nullptr;
    }
    if (hMapFile_) {
        CloseHandle(hMapFile_);
        hMapFile_ = nullptr;
    }
    if (hReloadEvent_) {
        CloseHandle(hReloadEvent_);
        hReloadEvent_ = nullptr;
    }
    isWriter_ = false;
}

bool SharedStatusManager::EnsureWriterMapped() {
    if (pSharedData_ && isWriter_) return true;

    // 如果之前以 Reader 方式打开，先关闭
    if (pSharedData_) Close();

    // 配置允许所有权限访问的 NULL DACL，确保 Session 0 (服务) 与 Session 1 (桌面) 均可互通
    SECURITY_DESCRIPTOR sd = {};
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&sd, TRUE, nullptr, FALSE);
    SECURITY_ATTRIBUTES sa = {};
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = &sd;
    sa.bInheritHandle = FALSE;

    hMapFile_ = CreateFileMappingW(
        INVALID_HANDLE_VALUE,
        &sa,
        PAGE_READWRITE,
        0,
        sizeof(ServiceSharedData),
        SHARED_MEM_GLOBAL
    );

    if (!hMapFile_ && GetLastError() == ERROR_ACCESS_DENIED) {
        hMapFile_ = CreateFileMappingW(
            INVALID_HANDLE_VALUE,
            &sa,
            PAGE_READWRITE,
            0,
            sizeof(ServiceSharedData),
            SHARED_MEM_LOCAL
        );
    }

    if (!hMapFile_) return false;

    pSharedData_ = (ServiceSharedData*)MapViewOfFile(hMapFile_, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(ServiceSharedData));
    if (!pSharedData_) {
        CloseHandle(hMapFile_);
        hMapFile_ = nullptr;
        return false;
    }

    if (!hReloadEvent_) {
        hReloadEvent_ = CreateEventW(&sa, FALSE, FALSE, SHARED_EVENT_GLOBAL);
        if (!hReloadEvent_ && GetLastError() == ERROR_ACCESS_DENIED) {
            hReloadEvent_ = CreateEventW(&sa, FALSE, FALSE, SHARED_EVENT_LOCAL);
        }
    }

    isWriter_ = true;
    return true;
}

bool SharedStatusManager::EnsureReaderMapped() {
    if (pSharedData_) return true;

    // 优先以 FILE_MAP_ALL_ACCESS 打开（以便桌面控制台可向 reqCloseConnId 写入指令）
    hMapFile_ = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, SHARED_MEM_GLOBAL);
    if (!hMapFile_) {
        hMapFile_ = OpenFileMappingW(FILE_MAP_READ, FALSE, SHARED_MEM_GLOBAL);
    }
    if (!hMapFile_) {
        hMapFile_ = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, SHARED_MEM_LOCAL);
    }
    if (!hMapFile_) {
        hMapFile_ = OpenFileMappingW(FILE_MAP_READ, FALSE, SHARED_MEM_LOCAL);
    }

    if (!hMapFile_) return false;

    pSharedData_ = (ServiceSharedData*)MapViewOfFile(hMapFile_, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(ServiceSharedData));
    if (!pSharedData_) {
        pSharedData_ = (ServiceSharedData*)MapViewOfFile(hMapFile_, FILE_MAP_READ, 0, 0, sizeof(ServiceSharedData));
    }

    if (!pSharedData_) {
        CloseHandle(hMapFile_);
        hMapFile_ = nullptr;
        return false;
    }

    isWriter_ = false;
    return true;
}

bool SharedStatusManager::WriteStatus(
    bool isRunning,
    int activeConnections,
    int64_t uploadSpeed,
    int64_t downloadSpeed,
    int64_t totalUpload,
    int64_t totalDownload,
    const std::vector<RealtimeConnection>& conns
) {
    if (!EnsureWriterMapped()) return false;

    pSharedData_->magic = SHARED_MAGIC;
    pSharedData_->version = 3;
    pSharedData_->updateTick = GetTickCount64();
    pSharedData_->isRunning = isRunning ? 1 : 0;
    pSharedData_->activeConnections = activeConnections;
    pSharedData_->uploadSpeed = uploadSpeed;
    pSharedData_->downloadSpeed = downloadSpeed;
    pSharedData_->totalUpload = totalUpload;
    pSharedData_->totalDownload = totalDownload;
    pSharedData_->uptime = ProxyServer::Instance().GetUptime();

    // 写入实时连接快照（最多保留 MAX_SHARED_CONNS 条）
    uint32_t count = (uint32_t)(std::min)(conns.size(), MAX_SHARED_CONNS);
    pSharedData_->connCount = count;
    for (uint32_t i = 0; i < count; ++i) {
        const auto& src = conns[i];
        auto& dst = pSharedData_->conns[i];
        dst.id = src.id;
        SafeCopyStr(dst.timestamp, sizeof(dst.timestamp), src.timestamp);
        SafeCopyStr(dst.username, sizeof(dst.username), src.username);
        SafeCopyStr(dst.clientIP, sizeof(dst.clientIP), src.clientIP);
        SafeCopyStr(dst.inboundType, sizeof(dst.inboundType), src.inboundType.empty() ? "HTTP" : src.inboundType);
        SafeCopyStr(dst.targetHost, sizeof(dst.targetHost), src.targetHost);
        dst.targetPort = src.targetPort;
        SafeCopyStr(dst.proxyDesc, sizeof(dst.proxyDesc), src.proxyDesc);
        dst.uploadBytes = src.uploadBytes;
        dst.downloadBytes = src.downloadBytes;
        dst.active = src.active ? 1 : 0;
    }

    return true;
}

bool SharedStatusManager::ReadStatus(
    bool& isRunning,
    int& activeConnections,
    int64_t& uploadSpeed,
    int64_t& downloadSpeed,
    int64_t& totalUpload,
    int64_t& totalDownload,
    int64_t* outUptime
) {
    if (!EnsureReaderMapped()) return false;
    if (pSharedData_->magic != SHARED_MAGIC) return false;

    uint64_t now = GetTickCount64();
    // 心跳超过 3000ms 视为服务已失联或停止
    if (now > pSharedData_->updateTick && (now - pSharedData_->updateTick) > 3000) {
        return false;
    }

    isRunning = (pSharedData_->isRunning != 0);
    activeConnections = pSharedData_->activeConnections;
    uploadSpeed = pSharedData_->uploadSpeed;
    downloadSpeed = pSharedData_->downloadSpeed;
    totalUpload = pSharedData_->totalUpload;
    totalDownload = pSharedData_->totalDownload;
    if (outUptime) *outUptime = pSharedData_->uptime;

    return true;
}

bool SharedStatusManager::ReadConnections(std::vector<RealtimeConnection>& conns) {
    conns.clear();
    if (!EnsureReaderMapped()) return false;
    if (pSharedData_->magic != SHARED_MAGIC) return false;

    uint64_t now = GetTickCount64();
    if (now > pSharedData_->updateTick && (now - pSharedData_->updateTick) > 4000) {
        return false;
    }

    uint32_t count = (std::min)(pSharedData_->connCount, (uint32_t)MAX_SHARED_CONNS);
    conns.reserve(count);

    for (uint32_t i = 0; i < count; ++i) {
        const auto& src = pSharedData_->conns[i];
        RealtimeConnection c;
        c.id = src.id;
        c.timestamp = src.timestamp;
        c.username = src.username;
        c.clientIP = src.clientIP;
        c.inboundType = src.inboundType[0] ? src.inboundType : "HTTP";
        c.targetHost = src.targetHost;
        c.targetPort = src.targetPort;
        c.proxyDesc = src.proxyDesc;
        c.uploadBytes = src.uploadBytes;
        c.downloadBytes = src.downloadBytes;
        c.active = (src.active != 0);
        conns.push_back(std::move(c));
    }

    return true;
}

bool SharedStatusManager::RequestCloseConnection(uint64_t connId) {
    if (!EnsureReaderMapped()) return false;
    if (pSharedData_->magic != SHARED_MAGIC) return false;
    pSharedData_->reqCloseConnId = connId;
    return true;
}

uint64_t SharedStatusManager::GetAndClearCloseConnectionRequest() {
    if (!pSharedData_) return 0;
    if (pSharedData_->magic != SHARED_MAGIC) return 0;
    uint64_t req = pSharedData_->reqCloseConnId;
    if (req != 0) {
        pSharedData_->reqCloseConnId = 0;
    }
    return req;
}

bool SharedStatusManager::NotifyRulesChanged() {
    if (!EnsureReaderMapped() && !EnsureWriterMapped()) return false;
    if (!pSharedData_) return false;

    pSharedData_->reqReloadRules = 1;

    HANDLE hEvent = OpenEventW(EVENT_MODIFY_STATE, FALSE, SHARED_EVENT_GLOBAL);
    if (!hEvent) {
        hEvent = OpenEventW(EVENT_MODIFY_STATE, FALSE, SHARED_EVENT_LOCAL);
    }
    if (hEvent) {
        SetEvent(hEvent);
        CloseHandle(hEvent);
    }
    return true;
}

bool SharedStatusManager::NotifyPortsChanged() {
    if (!EnsureReaderMapped() && !EnsureWriterMapped()) return false;
    if (!pSharedData_) return false;

    pSharedData_->reqReloadPorts = 1;

    HANDLE hEvent = OpenEventW(EVENT_MODIFY_STATE, FALSE, SHARED_EVENT_GLOBAL);
    if (!hEvent) {
        hEvent = OpenEventW(EVENT_MODIFY_STATE, FALSE, SHARED_EVENT_LOCAL);
    }
    if (hEvent) {
        SetEvent(hEvent);
        CloseHandle(hEvent);
    }
    return true;
}

bool SharedStatusManager::CheckAndClearReloadRequest(bool& outReloadRules, bool& outReloadPorts) {
    outReloadRules = false;
    outReloadPorts = false;

    if (!pSharedData_) {
        if (!EnsureWriterMapped() && !EnsureReaderMapped()) return false;
    }
    if (!pSharedData_) return false;
    if (pSharedData_->magic != SHARED_MAGIC) return false;

    if (pSharedData_->reqReloadRules != 0) {
        outReloadRules = true;
        pSharedData_->reqReloadRules = 0;
        pSharedData_->rulesVersion++;
    }
    if (pSharedData_->reqReloadPorts != 0) {
        outReloadPorts = true;
        pSharedData_->reqReloadPorts = 0;
        pSharedData_->portsVersion++;
    }
    return outReloadRules || outReloadPorts;
}

HANDLE SharedStatusManager::GetReloadEventHandle() {
    if (hReloadEvent_) return hReloadEvent_;

    SECURITY_DESCRIPTOR sd = {};
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&sd, TRUE, nullptr, FALSE);
    SECURITY_ATTRIBUTES sa = {};
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = &sd;
    sa.bInheritHandle = FALSE;

    hReloadEvent_ = CreateEventW(&sa, FALSE, FALSE, SHARED_EVENT_GLOBAL);
    if (!hReloadEvent_ && GetLastError() == ERROR_ACCESS_DENIED) {
        hReloadEvent_ = CreateEventW(&sa, FALSE, FALSE, SHARED_EVENT_LOCAL);
    }
    return hReloadEvent_;
}

bool SharedStatusManager::AddLogEntry(const ConnectionLogEntry& entry) {
    if (!EnsureWriterMapped()) return false;

    SharedLogItem item = {};
    SafeCopyStr(item.timestamp, sizeof(item.timestamp), entry.timestamp);
    SafeCopyStr(item.username, sizeof(item.username), entry.username);
    SafeCopyStr(item.clientIP, sizeof(item.clientIP), entry.clientIP);
    SafeCopyStr(item.inboundType, sizeof(item.inboundType), entry.inboundType.empty() ? "HTTP" : entry.inboundType);
    SafeCopyStr(item.targetHost, sizeof(item.targetHost), entry.targetHost);
    item.targetPort = entry.targetPort;
    SafeCopyStr(item.action, sizeof(item.action), entry.action);
    SafeCopyStr(item.proxyDesc, sizeof(item.proxyDesc), entry.proxyDesc);

    if (pSharedData_->logCount < MAX_SHARED_LOGS) {
        uint32_t idx = (pSharedData_->logHead + pSharedData_->logCount) % MAX_SHARED_LOGS;
        pSharedData_->logs[idx] = item;
        pSharedData_->logCount++;
    } else {
        // 队列满，覆盖最旧元素，推进 logHead
        pSharedData_->logs[pSharedData_->logHead] = item;
        pSharedData_->logHead = (pSharedData_->logHead + 1) % MAX_SHARED_LOGS;
    }

    return true;
}

bool SharedStatusManager::ReadRecentLogs(size_t limit, std::vector<ConnectionLogEntry>& logs) {
    logs.clear();
    if (!EnsureReaderMapped()) return false;
    if (pSharedData_->magic != SHARED_MAGIC) return false;

    uint32_t count = pSharedData_->logCount;
    if (count == 0) return true;
    if (count > MAX_SHARED_LOGS) count = MAX_SHARED_LOGS;

    uint32_t take = (uint32_t)(std::min)((size_t)count, limit);
    logs.reserve(take);

    // 从最旧到最新加入 logs，方便上层反向或顺序渲染
    // 队列中有效数据的起始索引为 (logHead + count - take) % MAX_SHARED_LOGS
    uint32_t startIdx = (pSharedData_->logHead + (count - take)) % MAX_SHARED_LOGS;
    for (uint32_t i = 0; i < take; ++i) {
        uint32_t cur = (startIdx + i) % MAX_SHARED_LOGS;
        const auto& src = pSharedData_->logs[cur];
        ConnectionLogEntry e;
        e.timestamp = src.timestamp;
        e.username = src.username;
        e.clientIP = src.clientIP;
        e.inboundType = src.inboundType[0] ? src.inboundType : "HTTP";
        e.targetHost = src.targetHost;
        e.targetPort = src.targetPort;
        e.action = src.action;
        e.proxyDesc = src.proxyDesc;
        logs.push_back(std::move(e));
    }

    return true;
}

bool SharedStatusManager::HasActiveHeartbeat() {
    if (!EnsureReaderMapped()) return false;
    if (pSharedData_->magic != SHARED_MAGIC) return false;
    uint64_t now = GetTickCount64();
    return (now >= pSharedData_->updateTick && (now - pSharedData_->updateTick) <= 3000 && pSharedData_->isRunning != 0);
}

