#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <cstdint>
#include <vector>
#include <string>
#include "ConnectionLogger.h"
#include "RealtimeConnectionManager.h"

#pragma pack(push, 8)
// 共享内存中的连接项结构
struct SharedConnectionItem {
    uint64_t id;
    char timestamp[24];      // "YYYY-MM-DD HH:MM:SS"
    char username[32];
    char clientIP[48];
    char targetHost[128];
    int32_t targetPort;
    char proxyDesc[64];
    int64_t uploadBytes;
    int64_t downloadBytes;
    int32_t active;          // 1: 活跃, 0: 已断开
    char inboundType[16];    // "HTTP", "HTTPS", "SOCKS5"
};

// 共享内存中的审计日志项结构
struct SharedLogItem {
    char timestamp[24];
    char username[32];
    char clientIP[48];
    char targetHost[128];
    int32_t targetPort;
    char action[32];
    char proxyDesc[64];
    char inboundType[16];    // "HTTP", "HTTPS", "SOCKS5"
};

static constexpr size_t MAX_SHARED_CONNS = 256;
static constexpr size_t MAX_SHARED_LOGS  = 128;

// 跨进程共享内存总控结构体
struct ServiceSharedData {
    uint32_t magic;              // 0x5052454C ('PREL')
    uint32_t version;            // 2
    uint64_t updateTick;         // GetTickCount64()
    int32_t  isRunning;          // 1 if running, 0 if stopped
    int32_t  activeConnections;  // Active connections count
    int64_t  uploadSpeed;        // bytes/sec
    int64_t  downloadSpeed;      // bytes/sec
    int64_t  totalUpload;        // total bytes
    int64_t  totalDownload;      // total bytes
    int64_t  uptime;             // uptime in seconds

    // 实时连接列表
    uint32_t connCount;
    SharedConnectionItem conns[MAX_SHARED_CONNS];

    // 控制台请求切断连接的 ID (GUI写入，服务读取并执行后置 0)
    uint64_t reqCloseConnId;

    // 实时审计日志环形队列
    uint32_t logCount;
    uint32_t logHead;
    SharedLogItem logs[MAX_SHARED_LOGS];

    // 跨进程控制与热重载信号（GUI 写入，服务读取消费后重置为 0）
    uint32_t reqReloadRules;     // 1: 请求重载分流规则
    uint32_t reqReloadPorts;     // 1: 请求重载代理端口与节点
    uint32_t rulesVersion;       // 分流规则版本序列号
    uint32_t portsVersion;       // 代理端口配置版本序列号
};
#pragma pack(pop)

// 跨进程（Windows 系统服务与桌面 GUI 控制台）状态与数据共享管理器
class SharedStatusManager {
public:
    static SharedStatusManager& Instance();

    // 核心/服务进程写入实时状态与连接快照（每秒调用）
    bool WriteStatus(
        bool isRunning,
        int activeConnections,
        int64_t uploadSpeed,
        int64_t downloadSpeed,
        int64_t totalUpload,
        int64_t totalDownload,
        const std::vector<RealtimeConnection>& conns
    );

    // 控制台进程读取实时状态（若数据新鲜度在 3 秒以内返回 true）
    bool ReadStatus(
        bool& isRunning,
        int& activeConnections,
        int64_t& uploadSpeed,
        int64_t& downloadSpeed,
        int64_t& totalUpload,
        int64_t& totalDownload,
        int64_t* outUptime = nullptr
    );

    // 控制台读取实时连接快照列表
    bool ReadConnections(std::vector<RealtimeConnection>& conns);

    // 控制台请求切断连接
    bool RequestCloseConnection(uint64_t connId);

    // 服务端读取并消费切断连接请求（返回 0 表示无请求）
    uint64_t GetAndClearCloseConnectionRequest();

    // 控制台请求服务重新加载分流规则（更新共享内存并唤醒重载事件）
    bool NotifyRulesChanged();

    // 控制台请求服务重新加载代理端口/节点配置
    bool NotifyPortsChanged();

    // 服务端检查并消费重载请求（返回是否有重载需求）
    bool CheckAndClearReloadRequest(bool& outReloadRules, bool& outReloadPorts);

    // 获取命名事件句柄（用于服务主线程事件驱动等待）
    HANDLE GetReloadEventHandle();

    // 服务端添加一条审计日志到共享队列
    bool AddLogEntry(const ConnectionLogEntry& entry);

    // 控制台读取最近的审计日志列表
    bool ReadRecentLogs(size_t limit, std::vector<ConnectionLogEntry>& logs);

    // 检查后台服务是否有活跃的实时心跳
    bool HasActiveHeartbeat();

    // 关闭映射
    void Close();

private:
    SharedStatusManager();
    ~SharedStatusManager();

    bool EnsureWriterMapped();
    bool EnsureReaderMapped();

    HANDLE hMapFile_ = nullptr;
    HANDLE hReloadEvent_ = nullptr;
    ServiceSharedData* pSharedData_ = nullptr;
    bool isWriter_ = false;
};
