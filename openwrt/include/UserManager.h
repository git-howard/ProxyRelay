#pragma once

#include "Common.h"
#include "Database.h"
#include <string>

class UserManager {
public:
    static UserManager& Instance();

    // 显式用户名/密码认证 (HTTP Basic / SOCKS5 握手认证)
    bool Authenticate(const std::string& username, const std::string& password,
                      const std::string& clientIP, UserInfo& user);

    // 透明代理免密认证：按局域网客户端源 IP 识别用户设备与所属配额策略
    bool AuthenticateByIP(const std::string& clientIP, UserInfo& user);

    // 检查流量限制 (月度和每日配额封顶检测)
    bool CheckTrafficLimit(int userId);

    // 检查 IP 是否在用户白名单内
    bool CheckIPAllowed(int userId, const std::string& clientIP);

    // 检查目标是否在用户的容许访问列表中
    static bool IsTargetAllowed(const std::string& targetIP, const std::string& targetDomain,
                                const std::string& allowedTargets);

    // 缓存失效与获取
    void InvalidateCache();
    std::vector<UserInfo> GetCachedUsers();

private:
    UserManager() = default;

    std::mutex cacheMutex_;
    std::vector<UserInfo> cachedUsers_;
    std::chrono::steady_clock::time_point lastCacheTime_{};
};
