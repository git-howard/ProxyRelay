#pragma once

#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <functional>
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
    std::string expiryDate;      // 账户到期日期 (YYYY-MM-DD)，空表示不限制
    std::string allowedTargets;  // 容许访问的目标（IP/CIDR/域名，逗号分隔，*表示无限制）
    int priority = 0;            // 优先级，数值越小优先级越高
    std::string quotaResetMonth;       // 配额重置月份 (YYYY-MM)
    int64_t quotaOffsetBytes = 0;      // 配额重置时当月已消耗字节偏移量
    std::string quotaResetDate;        // 配额重置日期 (YYYY-MM-DD)
    int64_t dailyQuotaOffsetBytes = 0; // 配额重置时当日已消耗字节偏移量
    std::string createdAt;
    std::string updatedAt;
};

// 代理端口配置
struct ProxyPort {
    int id = 0;
    int listenPort;              // 监听端口
    std::string upstreamType;    // 上游代理类型: "http", "socks5", "xray", "clash"
    std::string upstreamHost;    // 上游代理地址
    int upstreamPort;            // 上游代理端口
    std::string upstreamUser;    // 上游代理用户名
    std::string upstreamPass;    // 上游代理密码
    bool enabled = true;
    bool autoCheck = true;       // 是否启用TCPing自动检查可用性
    std::string description;
    int priority = 0;            // 优先级，数值越小优先级越高
    std::string groupName;       // 节点分组 (如 "日本节点", "香港专线", "默认")
    std::string xrayConfig;      // Xray 配置 JSON (当 upstreamType == "xray" 时使用)
    std::string clashConfig;     // Clash 生成的完整 YAML 配置 (当 upstreamType == "clash" 时使用)
    int clashSubscriptionId = 0; // 关联的 Clash 订阅 ID，0=不关联
    std::string clashNodeName;   // Clash 节点名称（用于订阅更新时匹配）
    std::string allowedTargets = "*"; // 上游容许目标，默认 * 表示不限制
    std::string createdAt;
};

// Clash 订阅信息
struct ClashSubscription {
    int id = 0;
    std::string name;                    // 订阅名称（用户自定义）
    std::string url;                     // 订阅 URL
    std::string rawContent;              // 缓存的原始 YAML 内容
    int updateIntervalDays = 0;          // 更新周期（天），0=不自动更新，>=1
    std::string updateTime = "04:00";    // 每天更新时间 HH:MM
    std::string lastUpdated;             // 上次更新时间 (ISO格式)
    std::string createdAt;
    
    // 订阅网站流量及有效期信息 (从 Subscription-Userinfo 等解析)
    int64_t uploadBytes = 0;             // 已用上传流量
    int64_t downloadBytes = 0;           // 已用下载流量
    int64_t totalBytes = 0;              // 总流量配额 (0表示未提供或无限制)
    std::string expireTime;              // 有效期截止时间 (YYYY-MM-DD HH:MM:SS 或 "长期有效")
    std::string websiteUrl;              // 官网/用户中心地址
    std::string includeFilter;           // 筛选节点规则 (例如: 香港 或 台湾&bgp 或 新加坡&bgp&奈飞)
    std::string excludeFilter;           // 排除节点规则 (例如: 香港 或 台湾&bgp 或 新加坡&bgp&奈飞)
    
    // 流量重置周期与起始日期配置
    int resetCycleDays = 0;              // 流量重置周期（天），0=当月自然月(根据实际大小月天数)，>0 为自定义固定天数
    std::string resetStartDate;          // 周期起始日期 (YYYY-MM-DD)，默认开启订阅日期
    int64_t cycleOffsetBytes = 0;        // 周期重置基准偏移量（字节）
    int lastResetCycle = 0;              // 上次已重置的周期序号
};

// 流量记录
struct TrafficRecord {
    int id = 0;
    int userId;
    std::string date;            // 日期 YYYY-MM-DD
    int64_t uploadBytes = 0;
    int64_t downloadBytes = 0;
    std::string updatedAt;
};

// 每日日流量汇总（供柱状图与统计）
struct DailyTrafficSummary {
    std::string date;            // 日期 YYYY-MM-DD
    int64_t uploadBytes = 0;
    int64_t downloadBytes = 0;
    int64_t totalBytes = 0;
};

// 月度流量汇总（供年度各月流量分析与统计）
struct MonthlyTrafficSummary {
    std::string month;           // 月份 YYYY-MM
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

// 路由规则
struct RoutingRule {
    int id = 0;
    int priority = 0;            // 优先级，数值越小优先级越高
    std::string matchType;       // 匹配类型: "cidr", "domain", "all"
    std::string matchValue;      // 匹配值: IP/CIDR 或 域名
    int proxyId = 0;             // 使用的代理ID，0表示直连, -2表示拒绝连接, -3表示按分组路由
    std::string targetGroup;     // 路由目标分组 (如 "日本节点", "香港专线")
    bool enabled = true;
    std::string description;
    std::string createdAt;
    bool isFallback = false;     // 是否为默认兜底规则
};

// 实时流量数据点
struct TrafficDataPoint {
    int64_t timestamp;
    int64_t bytesPerSecond;
};

class Database {
public:
    static Database& Instance();
    
    bool Initialize(const std::string& dbPath = "proxy.db");
    void Close();
    int GetDataVersion();
    
    // 用户管理
    bool AddUser(const UserInfo& user);
    bool UpdateUser(const UserInfo& user);
    bool DeleteUser(int userId);
    bool GetUser(int userId, UserInfo& user);
    bool GetUserByName(const std::string& username, UserInfo& user);
    std::vector<UserInfo> GetAllUsers();
    bool MoveUserUp(int userId);
    bool MoveUserDown(int userId);
    
    // 代理端口管理
    bool AddProxyPort(const ProxyPort& port);
    bool UpdateProxyPort(const ProxyPort& port);
    bool DeleteProxyPort(int portId);
    bool GetProxyPort(int portId, ProxyPort& port);
    std::vector<ProxyPort> GetAllProxyPorts();
    std::vector<ProxyPort> GetEnabledProxyPorts();
    void RepairClashPorts();
    
    // 流量统计
    bool RecordTraffic(int userId, int64_t uploadBytes, int64_t downloadBytes);
    bool RecordPortTraffic(int portId, int64_t uploadBytes, int64_t downloadBytes);
    bool GetDailyTraffic(int userId, const std::string& date, TrafficRecord& record);
    bool GetMonthlyTraffic(int userId, const std::string& month, int64_t& upload, int64_t& download);
    bool GetUserWeeklyTraffic(int userId, const std::string& weekStartDate, const std::string& today, int64_t& upload, int64_t& download);
    std::vector<TrafficRecord> GetUserTrafficHistory(int userId, int days = 30);
    std::vector<TrafficRecord> GetAllUsersTrafficToday();
    
    // 端口流量统计（自然周期）
    bool GetPortDailyTraffic(int portId, const std::string& date, int64_t& upload, int64_t& download);
    bool GetPortWeeklyTraffic(int portId, const std::string& weekStartDate, const std::string& today, int64_t& upload, int64_t& download);
    bool GetPortMonthlyTraffic(int portId, const std::string& month, int64_t& upload, int64_t& download);
    bool GetPortLastMonthTraffic(int portId, const std::string& lastMonth, int64_t& upload, int64_t& download);

    // 近N天日流量统计 (userId == -1 表示所有用户)
    std::vector<DailyTrafficSummary> GetDailyTrafficHistory(int days = 30, int userId = -1);

    // 流量趋势分析统计 (支持 mode: "month", "week", "day")
    std::vector<TrafficTrendItem> GetTrafficTrend(const std::string& mode = "day", int count = 90, int userId = -1);

    // 节点/端口 30天日流量历史 (portId <= 0 表示所有节点全量汇总)
    std::vector<DailyTrafficSummary> GetPortDailyTrafficHistory(int days = 30, int portId = -1);

    // 节点/端口 年度月流量统计 (portId <= 0 表示所有节点全量汇总; year <= 0 表示当前年)
    std::vector<MonthlyTrafficSummary> GetPortAnnualTrafficHistory(int year = 0, int portId = -1);

    // 获取节点存在流量记录的年份列表
    std::vector<int> GetPortTrafficYears();

    // 获取用户今日/本月已用流量
    int64_t GetUserDailyUsage(int userId);
    int64_t GetUserMonthlyUsage(int userId);
    int64_t GetUserLastMonthUsage(int userId);  // 上月流量
    int64_t GetUserTotalUsage(int userId);       // 总流量
    bool GetTotalTraffic(int64_t& upload, int64_t& download); // 全局历史总流量统计
    bool ResetUserTraffic(int userId);           // 重置用户流量额度（仅重置额度基准，保留总累计用量与历史记录）
    void CleanOldTrafficRecords(int userDays = 365, int portDays = 60); // 清理超期历史流量明细
    bool GetTrafficStorageInfo(int64_t& recordCount, int64_t& totalBytes, int& dayCount);
    bool GetPortTrafficStorageInfo(int64_t& recordCount, int64_t& totalBytes, int& dayCount);
    
    // 系统配置管理
    bool SetConfig(const std::string& key, const std::string& value);
    std::string GetConfig(const std::string& key, const std::string& defaultValue = "");
    
    // 代理优先级调整（支持组内移动）
    bool MoveProxyPortUp(int portId, const std::string& groupName = "");
    bool MoveProxyPortDown(int portId, const std::string& groupName = "");
    std::vector<std::string> GetAllPortGroups();
    bool RenamePortGroup(const std::string& oldName, const std::string& newName);
    static std::string InferNodeGroup(const std::string& name, const std::string& desc = "");
    
    // Clash 订阅管理
    bool AddSubscription(const ClashSubscription& sub);
    bool UpdateSubscription(const ClashSubscription& sub);
    bool DeleteSubscription(int subId);
    bool GetSubscription(int subId, ClashSubscription& sub);
    std::vector<ClashSubscription> GetAllSubscriptions();
    std::vector<ProxyPort> GetPortsBySubscriptionId(int subId);
    bool DeletePortsBySubscriptionId(int subId);
    int DeduplicateProxyPorts();         // 代理节点消重 (保留首条，移除冗余重复端口)
    
    // 路由规则管理
    bool AddRoutingRule(const RoutingRule& rule);
    bool UpdateRoutingRule(const RoutingRule& rule);
    bool DeleteRoutingRule(int ruleId);
    bool GetRoutingRule(int ruleId, RoutingRule& rule);
    std::vector<RoutingRule> GetAllRoutingRules();
    std::vector<RoutingRule> GetEnabledRoutingRules();
    bool MoveRoutingRuleUp(int ruleId);
    bool MoveRoutingRuleDown(int ruleId);
    void EnsureFallbackRule();
    
    // 流量统计持久化存储
    bool SavePortTrafficStats(int portId, int64_t upload1h, int64_t download1h,
                              int64_t upload24h, int64_t download24h,
                              int64_t uploadWeek, int64_t downloadWeek,
                              int64_t uploadMonth, int64_t downloadMonth,
                              int64_t uploadLastMonth, int64_t downloadLastMonth);
    bool LoadPortTrafficStats(int portId, int64_t& upload1h, int64_t& download1h,
                              int64_t& upload24h, int64_t& download24h,
                              int64_t& uploadWeek, int64_t& downloadWeek,
                              int64_t& uploadMonth, int64_t& downloadMonth,
                              int64_t& uploadLastMonth, int64_t& downloadLastMonth);
    bool SaveUserTrafficStats(int userId, int64_t upload1h, int64_t download1h,
                              int64_t upload24h, int64_t download24h,
                              int64_t uploadWeek, int64_t downloadWeek,
                              int64_t uploadMonth, int64_t downloadMonth,
                              int64_t uploadLastMonth, int64_t downloadLastMonth);
    bool LoadUserTrafficStats(int userId, int64_t& upload1h, int64_t& download1h,
                              int64_t& upload24h, int64_t& download24h,
                              int64_t& uploadWeek, int64_t& downloadWeek,
                              int64_t& uploadMonth, int64_t& downloadMonth,
                              int64_t& uploadLastMonth, int64_t& downloadLastMonth);
    std::vector<int> GetAllPortIds();
    std::vector<int> GetAllUserIds();

    // 封禁管理
    struct BanInfo {
        int id;
        std::string ip;
        std::string remark;     // 用于黑白名单
        int64_t expiryTime;     // 用于自动封禁
        std::string createdAt;
    };

    // 白名单
    bool AddToWhitelist(const std::string& ip, const std::string& remark);
    bool UpdateWhitelist(int id, const std::string& ip, const std::string& remark);
    bool RemoveFromWhitelist(int id);
    std::vector<BanInfo> GetWhitelist();
    bool IsWhitelisted(const std::string& ip);

    // 黑名单
    bool AddToBlacklist(const std::string& ip, const std::string& remark);
    bool UpdateBlacklist(int id, const std::string& ip, const std::string& remark);
    bool RemoveFromBlacklist(int id);
    bool RemoveBlacklistByIP(const std::string& ip);
    std::vector<BanInfo> GetBlacklist();
    bool IsBlacklisted(const std::string& ip);

    // 自动封禁
    bool AddToAutoBan(const std::string& ip, int64_t expiryTime);
    bool RemoveFromAutoBan(int id);
    bool RemoveAutoBanByIP(const std::string& ip);
    bool ClearAllAutoBans();
    std::vector<BanInfo> GetAutoBanList();
    bool IsAutoBanned(const std::string& ip);
    void CleanExpiredAutoBans();

    // 免认证IP
    bool AddToNoAuthList(const std::string& ip, const std::string& remark);
    bool UpdateNoAuthList(int id, const std::string& ip, const std::string& remark);
    bool RemoveFromNoAuthList(int id);
    std::vector<BanInfo> GetNoAuthList();
    bool IsNoAuthIP(const std::string& ip);

    // 登录失败记录
    bool RecordLoginFailure(const std::string& ip);
    int GetLoginFailures(const std::string& ip, int minutes);
    void CleanOldLoginFailures(int minutes);
    void RecordAuthFailure(const std::string& ip);
    void ClearAuthFailure(const std::string& ip);

    // 应用代理规则（全局代理按进程名路由）
    struct AppProxyRule {
        int id = 0;
        std::string appName;         // 进程名，如 "chrome.exe"，"*" 表示所有应用
        int proxyId = -1;            // 目标代理 ID，0=直连，-1=默认行为
        int priority = 0;            // 优先级，数值越小优先级越高
        bool enabled = true;
        std::string description;
        std::string createdAt;
    };

    bool AddAppProxyRule(const AppProxyRule& rule);
    bool UpdateAppProxyRule(const AppProxyRule& rule);
    bool DeleteAppProxyRule(int ruleId);
    bool GetAppProxyRule(int ruleId, AppProxyRule& rule);
    std::vector<AppProxyRule> GetAllAppProxyRules();
    std::vector<AppProxyRule> GetEnabledAppProxyRules();

    // 跨平台配置导出与导入 (JSON 格式，Windows 与 OpenWrt 互通)
    nlohmann::json ExportConfig();
    bool ImportConfig(const nlohmann::json& config, bool overwrite, std::string& errorMsg);

private:
    Database() = default;
    ~Database();
    Database(const Database&) = delete;
    Database& operator=(const Database&) = delete;
    
    bool CreateTables();
    bool ExecuteSQL(const std::string& sql);
    
    sqlite3* db_ = nullptr;
    std::recursive_mutex mutex_;  // Use recursive mutex to allow nested locking
    std::string dbPath_;
};
