#pragma once
#include <string>
#include <vector>
#include <mutex>
#include <unordered_set>
#include "Database.h"

struct CIDR {
    unsigned int ip;
    unsigned int mask;
};

struct BypassConfig {
    bool enableChnRoute;
    bool enableChnRoute6;
    bool enableChnList;
    std::string customRules;
};

// 缓存的路由规则（包含解析后的匹配数据）
struct ParsedRoutingRule {
    int id;
    int priority;
    std::string matchType;      // "cidr", "domain", "all"
    std::string matchValue;
    int proxyId;
    std::string targetGroup;    // 当指定目标分组时使用
    bool enabled;
    bool isFallback = false;
    // 解析后的数据
    std::vector<CIDR> cidrs;           // 当 matchType == "cidr" 时
    std::vector<std::string> domains;  // 当 matchType == "domain" 时
};

class RuleManager {
public:
    static RuleManager& Instance();

    // 初始化并加载配置
    void Initialize();
    
    // 设置/获取黑名单规则（直接文本，逗号或换行分隔）
    void SetBlacklist(const std::string& rules);
    std::string GetBlacklist() const;

    // 设置/获取Bypass配置
    void SetBypassConfig(const BypassConfig& config);
    BypassConfig GetBypassConfig() const;

    // 检查IP是否在黑名单中
    bool IsBlacklisted(const std::string& ip);

    // 检查是否应绕过代理（直连）- 旧接口，兼容保留
    bool ShouldBypass(const std::string& ip, const std::string& domain);
    
    // 获取匹配的代理ID及目标分组
    // 返回值: 匹配的代理ID，0表示直连，-1表示无匹配（使用默认代理），-2表示拒绝连接，-3表示匹配到目标分组 (此时 outGroup 返回对应分组名称)
    int GetMatchingProxyId(const std::string& ip, const std::string& domain, std::string* outGroup = nullptr);
    
    // 重新加载路由规则
    void ReloadRoutingRules();

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
    void TriggerUpdate(); // 手动更新

private:
    RuleManager();
    ~RuleManager();
    
    void ParseCIDRList(const std::string& content, std::vector<CIDR>& list);
    void ParseCustomRules(const std::string& content);  // 解析自定义规则（IP/CIDR和域名）
    bool MatchCIDR(const std::string& ip, const std::vector<CIDR>& list);
    bool MatchDomain(const std::string& domain, const std::vector<std::string>& rules);
    bool WildcardMatch(const std::string& str, const std::string& pattern);
    
    void UpdateThreadFunc();
    void DownloadRules();
    void AutoUpdateLoop();
    
    std::string blacklistRules_;
    std::vector<CIDR> blacklistCIDRs_;
    
    BypassConfig bypassConfig_;
    std::vector<CIDR> chnRoute_;
    std::vector<std::string> chnList_; // 简单的域名后缀列表
    std::vector<CIDR> customBypassCIDRs_;
    std::vector<std::string> customBypassDomains_;

    // 中国国内流量直连配置
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

    // 国内 IP 订阅属性
    std::string chinaIpSubUrl_;
    int chinaIpSubIntervalDays_ = 7;
    std::string chinaIpLastUpdate_;
    int chinaIpCidrCount_ = 0;
    std::thread autoUpdateThread_;
    bool autoUpdateRunning_ = false;
    
    // 路由规则缓存
    std::vector<ParsedRoutingRule> routingRules_;

    mutable std::mutex mutex_;
    bool running_ = false;
};

