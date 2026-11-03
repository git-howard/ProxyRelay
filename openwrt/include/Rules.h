#pragma once

#include "Common.h"
#include "Database.h"
#include <string>
#include <vector>
#include <mutex>
#include <thread>
#include <atomic>
#include <unordered_set>

struct CIDR {
    unsigned int ip;
    unsigned int mask;
};

struct ParsedRoutingRule {
    int id;
    int priority;
    std::string matchType;      // "cidr", "domain", "all"
    std::string matchValue;
    int proxyId;
    std::string targetGroup;
    bool enabled;
    bool isFallback = false;
    std::vector<CIDR> cidrs;
    std::vector<std::string> domains;
    std::vector<std::string> patterns;
};

class RuleManager {
public:
    static RuleManager& Instance();

    void Initialize();
    void ReloadRoutingRules();

    // 匹配路由规则获取目标代理出口
    // 0: 直连
    // -1: 默认
    // -2: 拒绝/阻断
    // -3: 走目标分组 (outGroup 返回分组名)
    // >0: 走特定代理节点 ID
    int GetMatchingProxyId(const std::string& ip, const std::string& domain, std::string* outGroup = nullptr, bool* outIsFallback = nullptr);

    // 检查 IP 是否直连/绕过
    bool IsDirectIP(const std::string& ip);

    // 中国国内流量直连配置与判断
    void LoadChinaDirectConfig();
    bool IsChinaTraffic(const std::string& ip, const std::string& domain);
    bool IsChinaTrafficLocked(const std::string& ip, const std::string& domain);
    bool IsChinaDirectEnabled() const { return chinaDirectEnabled_; }

    // 国内 IP 规则订阅管理
    std::string GetChinaIpSubUrl() const;
    void SetChinaIpSubUrl(const std::string& url);
    int GetChinaIpSubIntervalDays() const;
    void SetChinaIpSubIntervalDays(int days);
    std::string GetChinaIpLastUpdate() const;
    int GetChinaIpCidrCount() const;
    bool UpdateChinaIpSubscription(const std::string& customUrl = "", int* outCount = nullptr, std::string* outError = nullptr);

    // 自动更新规则（在后台线程）
    void StartAutoUpdate();
    void StopAutoUpdate();

private:
    RuleManager();
    ~RuleManager();

    void ParseCIDRList(const std::string& content, std::vector<CIDR>& list);
    void ParseCustomRules(const std::string& content);
    bool MatchCIDR(const std::string& ip, const std::vector<CIDR>& list);
    bool MatchDomain(const std::string& domain, const std::vector<std::string>& rules);
    bool WildcardMatch(const std::string& str, const std::string& pattern);
    bool DownloadHttpContent(const std::string& url, std::string& outContent, std::string& outErr);
    void AutoUpdateLoop();

    mutable std::mutex mutex_;
    std::vector<ParsedRoutingRule> parsedRules_;

    // 国内直连选项
    bool chinaDirectEnabled_ = true;
    bool chinaDirectCnDomains_ = true;
    bool chinaDirectPopularSites_ = true;
    bool chinaDirectIps_ = true;
    bool chinaDirectLan_ = true;
    std::string chinaDirectCustom_;

    std::vector<CIDR> customChinaDirectCIDRs_;
    std::vector<std::string> customChinaDirectDomains_;
    std::vector<CIDR> lanCIDRs_;
    std::vector<std::string> popularChinaDomains_;
    std::vector<CIDR> chnRoute_;

    // 国内 IP 订阅
    std::string chinaIpSubUrl_;
    int chinaIpSubIntervalDays_ = 7;
    std::string chinaIpLastUpdate_;
    int chinaIpCidrCount_ = 0;

    // 自动更新线程
    std::atomic<bool> autoUpdateRunning_{false};
    std::thread autoUpdateThread_;
};
