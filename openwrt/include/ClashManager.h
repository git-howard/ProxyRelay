#pragma once

#include "Common.h"
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <thread>
#include <atomic>

// Clash 代理节点信息
struct ClashNode {
    std::string name;       // 节点名称
    std::string type;       // 代理类型: ss, vmess, trojan, vless, hysteria2, etc.
    std::string server;     // 服务器地址
    int port = 0;           // 端口
    std::string rawYaml;    // 原始 YAML 块
};

class ClashManager {
public:
    static ClashManager& Instance();

    bool Initialize();

    int StartClash(int portId, const std::string& configYaml);
    void StopClash(int portId);
    void StopAll();

    int GetLocalSocksPort(int portId);
    bool IsRunning(int portId);
    bool IsClashAvailable() const { return !clashPath_.empty(); }
    std::string GetClashPath() const { return clashPath_; }

    struct SubscriptionUserInfo {
        int64_t uploadBytes = 0;
        int64_t downloadBytes = 0;
        int64_t totalBytes = 0;
        std::string expireTime;
        std::string websiteUrl;
        std::string startDate;
    };

    struct SubscriptionCycleInfo {
        int curCycle = 0;
        int daysPassed = 0;
        int daysRemaining = 0;
        int cycleTotalDays = 30;
        double cyclePercent = 0.0;
        std::string curCycleStart;
        std::string nextResetDate;
        bool isNaturalMonth = true;
        bool needReset = false;
    };

    static SubscriptionCycleInfo CalculateCycleInfo(const std::string& resetStartDateStr, int resetCycleDays, int lastResetCycle, const std::string& createdAt = "");

    static std::string DownloadSubscription(const std::string& url, SubscriptionUserInfo* outInfo = nullptr);
    static void ParseSubscriptionHeaders(const std::string& headers, SubscriptionUserInfo& info);
    static void ParseSubscriptionContentUserInfo(const std::string& content, SubscriptionUserInfo& info);

    static std::vector<ClashNode> ParseSubscriptionNodes(const std::string& yamlContent);
    static std::string GenerateNodeConfig(const ClashNode& node, int mixedPort);

    static bool MatchFilterRule(const std::string& text, const std::string& rule);
    static bool ShouldKeepNode(const ClashNode& node, const std::string& includeFilter, const std::string& excludeFilter);
    static std::vector<ClashNode> FilterAndDeduplicateNodes(const std::vector<ClashNode>& nodes, const std::string& includeFilter = "", const std::string& excludeFilter = "");

    int RefreshSubscription(int subscriptionId);

private:
    ClashManager();
    ~ClashManager();

    int FindAvailablePort();

    std::string clashPath_;
    std::recursive_mutex mutex_;
    struct ProcessInfo {
        pid_t pid = 0;
        int localPort = 0;
    };
    std::map<int, ProcessInfo> processes_;
};
