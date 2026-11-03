#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <windows.h>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <thread>
#include <atomic>

// Clash 节点信息（从订阅 YAML 中解析）
struct ClashNode {
    std::string name;       // 节点名称
    std::string type;       // 代理类型: ss, vmess, trojan, vless, hysteria2, etc.
    std::string server;     // 服务器地址
    int port = 0;           // 端口
    std::string rawYaml;    // 原始 YAML 块（带缩进的完整节点定义）
};

class ClashManager {
public:
    static ClashManager& Instance();
    
    // 初始化（查找 mihomo-windows-amd64.exe 或 clash.exe 路径）
    bool Initialize();
    
    // 统一实例管理：启动或重载包含所有订阅节点的单一 Mihomo 进程
    bool StartOrReloadUnified();

    // 为指定代理端口启动 clash 进程（统一模式下分配并映射 listener）
    // portId: 代理端口 ID
    // configYaml: 节点 yaml 配置（统一模式下会自动从数据库聚合）
    // 返回本地 SOCKS5/HTTP 混合端口号，失败返回 0
    int StartClash(int portId, const std::string& configYaml = "");
    
    // 获取运行中的 clash 统一子进程 PID
    std::vector<DWORD> GetAllProcessIds();
    
    // 停止指定代理端口的 clash 映射
    void StopClash(int portId);
    
    // 停止所有 clash 进程（终止统一实例）
    void StopAll();
    
    // 获取指定端口的本地 mixed-port
    int GetLocalSocksPort(int portId);
    
    // 检查 clash 是否正在运行
    bool IsRunning(int portId);
    
    // 检查 clash 核心是否可用
    bool IsClashAvailable() const { return !clashPath_.empty(); }
    std::string GetClashPath() const { return clashPath_; }
    
    // ========== 订阅管理功能 ==========
    
    struct SubscriptionUserInfo {
        int64_t uploadBytes = 0;
        int64_t downloadBytes = 0;
        int64_t totalBytes = 0;
        std::string expireTime;
        std::string websiteUrl;
        std::string startDate;   // 从订阅提取的流量起始日期 (YYYY-MM-DD)
    };

    struct SubscriptionCycleInfo {
        int curCycle = 0;
        int daysPassed = 0;
        int daysRemaining = 0;
        int cycleTotalDays = 30; // 当前自然月/周期的总天数 (如 31, 30, 28)
        double cyclePercent = 0.0;
        std::string curCycleStart;
        std::string nextResetDate;
        bool isNaturalMonth = true;
        bool needReset = false;
    };

    // 计算流量重置周期进度与状态
    static SubscriptionCycleInfo CalculateCycleInfo(const std::string& resetStartDateStr, int resetCycleDays, int lastResetCycle, const std::string& createdAt = "");

    // 通过 HTTP GET 下载订阅内容并可选解析流量/有效期信息
    static std::string DownloadSubscription(const std::string& url, SubscriptionUserInfo* outInfo = nullptr);
    static void ParseSubscriptionContentUserInfo(const std::string& content, SubscriptionUserInfo& info);
    
    // 解析 YAML 中的 proxies 部分，提取所有节点
    static std::vector<ClashNode> ParseSubscriptionNodes(const std::string& yamlContent);
    
    // 为单个节点生成完整的 mihomo 配置 YAML
    static std::string GenerateNodeConfig(const ClashNode& node, int mixedPort);

    // 规则匹配与过滤
    // rule 格式示例: "香港 或 台湾&bgp 或 新加坡&bgp&奈飞"
    static bool MatchFilterRule(const std::string& text, const std::string& rule);
    static bool ShouldKeepNode(const ClashNode& node, const std::string& includeFilter, const std::string& excludeFilter);
    static std::vector<ClashNode> FilterAndDeduplicateNodes(const std::vector<ClashNode>& nodes, const std::string& includeFilter = "", const std::string& excludeFilter = "");
    
    // 刷新指定订阅的所有关联端口配置
    // 返回更新的端口数量，-1 表示下载失败
    int RefreshSubscription(int subscriptionId);
    
    // 启动自动更新线程
    void StartAutoUpdate();
    
    // 停止自动更新线程
    void StopAutoUpdate();
    
private:
    ClashManager() = default;
    ~ClashManager();
    
    // 统一单一 Mihomo 实例私有管理方法
    bool StartOrReloadUnifiedInternal();
    void StopUnifiedInternal();
    bool IsUnifiedAliveInternal();
    int AllocatePortForPortId(int portId, const std::map<int, int>& existingMap);
    
    // 查找可用的本地端口
    int FindAvailablePort();
    
    // 自动更新循环
    void AutoUpdateLoop();
    
    std::string clashPath_;
    std::mutex mutex_;
    
    // 统一单一 Mihomo 进程管理
    HANDLE unifiedProcess_ = nullptr;
    HANDLE unifiedThread_ = nullptr;
    DWORD unifiedProcessId_ = 0;
    std::string unifiedConfigPath_;
    std::string lastUnifiedConfigContent_;
    std::map<int, int> portToLocalSocksPort_; // portId -> local mixed port
    
    // 自动更新线程
    std::thread autoUpdateThread_;
    std::atomic<bool> autoUpdateRunning_{false};
    
    // 端口分配范围 (30000 - 40000 避免和 xray 的 20000-30000 冲突)
    static const int PORT_RANGE_START = 30000;
    static const int PORT_RANGE_END = 40000;
    int nextPort_ = PORT_RANGE_START;
};
