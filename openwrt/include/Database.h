#pragma once

#include "Common.h"
#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include "sqlite3.h"
#include "json.hpp"

// 用户信息
struct UserInfo {
    int id = 0;
    std::string username;
    std::string password;
    std::string allowedIPs;      // 允许的IP地址列表（逗号分隔）
    int64_t dailyLimit = 0;      // 每日流量限制（字节），0表示无限制
    int64_t monthlyLimit = 0;    // 每月流量限制（字节），0表示无限制
    bool enabled = true;
    std::string remark;          // 备注
    std::string expiryDate;      // 账户到期日期 (YYYY-MM-DD)
    std::string allowedTargets;  // 容许访问的目标
    int priority = 0;
    std::string quotaResetMonth;
    int64_t quotaOffsetBytes = 0;
    std::string quotaResetDate;
    int64_t dailyQuotaOffsetBytes = 0;
    std::string createdAt;
    std::string updatedAt;
};

// 代理端口配置
struct ProxyPort {
    int id = 0;
    int listenPort = 0;          // 监听端口，0表示纯上游节点
    std::string upstreamType;    // "http", "socks5", "xray", "clash", "direct"
    std::string upstreamHost;
    int upstreamPort = 0;
    std::string upstreamUser;
    std::string upstreamPass;
    bool enabled = true;
    bool autoCheck = true;
    std::string description;
    int priority = 0;
    std::string groupName;       // 节点分组
    std::string xrayConfig;
    std::string clashConfig;
    int clashSubscriptionId = 0;
    std::string clashNodeName;
    std::string allowedTargets = "*";
    std::string createdAt;
};

// Clash 订阅信息
struct ClashSubscription {
    int id = 0;
    std::string name;
    std::string url;
    std::string rawContent;
    int updateIntervalDays = 0;
    std::string updateTime = "04:00";
    std::string lastUpdated;
    std::string createdAt;
    int64_t uploadBytes = 0;
    int64_t downloadBytes = 0;
    int64_t totalBytes = 0;
    std::string expireTime;
    std::string websiteUrl;
    std::string includeFilter;
    std::string excludeFilter;
    int resetCycleDays = 0;
    std::string resetStartDate;
    int64_t cycleOffsetBytes = 0;
    int lastResetCycle = 0;
};

// 流量统计记录
struct TrafficRecord {
    int id = 0;
    int userId = 0;
    std::string date;
    int64_t uploadBytes = 0;
    int64_t downloadBytes = 0;
    std::string updatedAt;
};

struct DailyTrafficSummary {
    std::string date;
    int64_t uploadBytes = 0;
    int64_t downloadBytes = 0;
    int64_t totalBytes = 0;
};

struct MonthlyTrafficSummary {
    std::string month;
    int64_t uploadBytes = 0;
    int64_t downloadBytes = 0;
    int64_t totalBytes = 0;
};

// 流量趋势分析项（按月/周/天）
struct TrafficTrendItem {
    std::string date;     // YYYY-MM-DD 或 YYYY-MM 或 YYYY-MM-DD~YYYY-MM-DD
    std::string label;    // 坐标轴标签 (如 26/10, 10/19, 10-21)
    std::string tooltip;  // 悬停提示文字 (如 2026年10月, 2026-10-19 ~ 2026-10-25, 2026-10-21)
    int64_t uploadBytes = 0;
    int64_t downloadBytes = 0;
    int64_t totalBytes = 0;
};

struct RoutingRule {
    int id = 0;
    int priority = 0;
    std::string matchType;      // "domain", "cidr", "all"
    std::string matchValue;
    int proxyId = 0;            // 0: 直连, -1: 默认, -2: 阻断, >0: 端口ID, -3: 节点分组
    std::string targetGroup;
    std::string description;
    bool enabled = true;
    bool isFallback = false;
    std::string createdAt;
};

struct BlacklistItem {
    int id = 0;
    std::string ip;
    std::string reason;
    std::string createdAt;
    int failCount = 0;
    std::string bannedUntil;
};

struct BanInfo {
    int id = 0;
    std::string ip;
    std::string remark;
    std::string createdAt;
};

class Database {
public:
    static Database& Instance();

    bool Initialize(const std::string& dbPath = "proxy.db");
    void Close();

    // 用户管理
    std::vector<UserInfo> GetAllUsers();
    bool GetUserById(int id, UserInfo& user);
    bool GetUserByUsername(const std::string& username, UserInfo& user);
    bool GetUserByIP(const std::string& clientIP, UserInfo& user);
    bool SaveUser(const UserInfo& user);
    bool DeleteUser(int id);
    bool ToggleUser(int id, bool enabled);
    bool MoveUserUp(int id);
    bool MoveUserDown(int id);
    bool ResetUserTraffic(int id);
    bool ResetUserTrafficOffset(int id) { return ResetUserTraffic(id); }

    // 端口管理
    std::vector<ProxyPort> GetAllProxyPorts();
    bool GetProxyPortById(int id, ProxyPort& port);
    bool SaveProxyPort(const ProxyPort& port);
    bool DeleteProxyPort(int id);
    bool ToggleProxyPort(int id, bool enabled);
    bool MoveProxyPortUp(int id, const std::string& group = "");
    bool MoveProxyPortDown(int id, const std::string& group = "");
    std::vector<std::string> GetAllPortGroups();
    bool RenamePortGroup(const std::string& oldName, const std::string& newName);

    // 流量记录
    bool RecordTraffic(int userId, int64_t uploadBytes, int64_t downloadBytes);
    bool RecordPortTraffic(int portId, int64_t uploadBytes, int64_t downloadBytes);
    void CleanOldTrafficRecords(int userDays = 365, int portDays = 60);
    int64_t GetUserMonthlyTraffic(int userId, const std::string& month = "");
    int64_t GetUserDailyTraffic(int userId, const std::string& date = "");
    int64_t GetUserTotalTraffic(int userId);
    int64_t GetUserTotalUsage(int userId) { return GetUserTotalTraffic(userId); }
    std::vector<DailyTrafficSummary> GetDailyTrafficHistory(int days = 30, int userId = -1);
    std::vector<TrafficTrendItem> GetTrafficTrend(const std::string& mode = "day", int count = 90, int userId = -1);
    std::vector<MonthlyTrafficSummary> GetMonthlyTrafficHistory(int year = 0, int userId = -1);
    std::vector<DailyTrafficSummary> GetPortDailyTrafficHistory(int days = 30, int portId = -1);
    std::vector<MonthlyTrafficSummary> GetPortAnnualTrafficHistory(int year = 0, int portId = -1);
    std::vector<int> GetPortTrafficYears();
    bool GetTrafficStorageInfo(int64_t& recordCount, int64_t& totalBytes, int& dayCount);
    bool GetPortTrafficStorageInfo(int64_t& recordCount, int64_t& totalBytes, int& dayCount);

    // 路由分流
    std::vector<RoutingRule> GetAllRoutingRules();
    bool SaveRoutingRule(const RoutingRule& rule);
    bool DeleteRoutingRule(int id);
    bool ToggleRoutingRule(int id, bool enabled);
    bool MoveRoutingRuleUp(int id);
    bool MoveRoutingRuleDown(int id);
    void EnsureFallbackRule();
    bool GetFallbackRule(RoutingRule& outRule);

    // 订阅管理
    std::vector<ClashSubscription> GetAllSubscriptions();
    bool GetSubscriptionById(int id, ClashSubscription& sub);
    bool SaveSubscription(ClashSubscription& sub);
    bool DeleteSubscription(int id);
    bool DeletePortsBySubscriptionId(int subId);
    std::vector<ProxyPort> GetPortsBySubscriptionId(int subId);
    int DeduplicateProxyPorts();

    // 黑名单、白名单与免认证 IP
    struct BanPolicy {
        bool enabled = true;
        int windowMinutes = 5;
        int maxFailures = 10;
        int banMinutes = 60;
    };
    BanPolicy GetBanPolicy();
    bool SaveBanPolicy(const BanPolicy& policy);

    std::vector<BlacklistItem> GetBlacklist();
    bool AddBlacklist(const std::string& ip, const std::string& reason);
    bool RemoveBlacklist(const std::string& ip);
    bool RemoveBlacklistById(int id);
    bool ClearAutoBans();
    bool IsIPBanned(const std::string& ip);
    void RecordAuthFailure(const std::string& ip);
    void ClearAuthFailure(const std::string& ip);

    std::vector<BanInfo> GetWhitelist();
    bool AddToWhitelist(const std::string& ip, const std::string& remark);
    bool RemoveFromWhitelist(int id);
    bool RemoveFromWhitelistByIP(const std::string& ip);
    bool IsWhitelisted(const std::string& ip);

    std::vector<BanInfo> GetNoAuthList();
    bool AddToNoAuthList(const std::string& ip, const std::string& remark);
    bool RemoveFromNoAuthList(int id);
    bool RemoveFromNoAuthListByIP(const std::string& ip);
    bool IsNoAuthIP(const std::string& ip);

    // 配置读取
    std::string GetConfig(const std::string& key, const std::string& defaultVal = "");
    bool SetConfig(const std::string& key, const std::string& value);

    // 跨平台配置导入与导出 (JSON 格式，Windows 与 OpenWrt 互通)
    nlohmann::json ExportConfig();
    bool ImportConfig(const nlohmann::json& config, bool overwrite, std::string& errorMsg);

private:
    Database() = default;
    ~Database();

    bool CreateTables();

    sqlite3* db_ = nullptr;
    mutable std::recursive_mutex mutex_;
};
