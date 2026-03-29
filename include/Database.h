#pragma once

#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <functional>
#include "sqlite3.h"

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
    int priority = 0;            // 优先级，数值越小优先级越高
    std::string createdAt;
    std::string updatedAt;
};

// 代理端口配置
struct ProxyPort {
    int id = 0;
    int listenPort;              // 监听端口
    std::string upstreamType;    // 上游代理类型: "http" 或 "socks5"
    std::string upstreamHost;    // 上游代理地址
    int upstreamPort;            // 上游代理端口
    std::string upstreamUser;    // 上游代理用户名
    std::string upstreamPass;    // 上游代理密码
    bool enabled = true;
    std::string description;
    int priority = 0;            // 优先级，数值越小优先级越高
    std::string createdAt;
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

// 路由规则
struct RoutingRule {
    int id = 0;
    int priority = 0;            // 优先级，数值越小优先级越高
    std::string matchType;       // 匹配类型: "cidr", "domain", "all"
    std::string matchValue;      // 匹配值: IP/CIDR 或 域名
    int proxyId = 0;             // 使用的代理ID，0表示直连
    bool enabled = true;
    std::string description;
    std::string createdAt;
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
    
    // 流量统计
    bool RecordTraffic(int userId, int64_t uploadBytes, int64_t downloadBytes);
    bool GetDailyTraffic(int userId, const std::string& date, TrafficRecord& record);
    bool GetMonthlyTraffic(int userId, const std::string& month, int64_t& upload, int64_t& download);
    std::vector<TrafficRecord> GetUserTrafficHistory(int userId, int days = 30);
    std::vector<TrafficRecord> GetAllUsersTrafficToday();
    
    // 获取用户今日/本月已用流量
    int64_t GetUserDailyUsage(int userId);
    int64_t GetUserMonthlyUsage(int userId);
    int64_t GetUserLastMonthUsage(int userId);  // 上月流量
    int64_t GetUserTotalUsage(int userId);       // 总流量
    
    // 系统配置管理
    bool SetConfig(const std::string& key, const std::string& value);
    std::string GetConfig(const std::string& key, const std::string& defaultValue = "");
    
    // 代理优先级调整
    bool MoveProxyPortUp(int portId);
    bool MoveProxyPortDown(int portId);
    
    // 路由规则管理
    bool AddRoutingRule(const RoutingRule& rule);
    bool UpdateRoutingRule(const RoutingRule& rule);
    bool DeleteRoutingRule(int ruleId);
    bool GetRoutingRule(int ruleId, RoutingRule& rule);
    std::vector<RoutingRule> GetAllRoutingRules();
    std::vector<RoutingRule> GetEnabledRoutingRules();
    bool MoveRoutingRuleUp(int ruleId);
    bool MoveRoutingRuleDown(int ruleId);
    
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
    std::vector<BanInfo> GetBlacklist();
    bool IsBlacklisted(const std::string& ip);

    // 自动封禁
    bool AddToAutoBan(const std::string& ip, int64_t expiryTime);
    bool RemoveFromAutoBan(int id);
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
