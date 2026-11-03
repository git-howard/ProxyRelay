#include "UserManager.h"
#include "Utils.h"

UserManager& UserManager::Instance() {
    static UserManager instance;
    return instance;
}

void UserManager::InvalidateCache() {
    std::lock_guard<std::mutex> lock(cacheMutex_);
    cachedUsers_.clear();
}

std::vector<UserInfo> UserManager::GetCachedUsers() {
    auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lock(cacheMutex_);
    if (!cachedUsers_.empty() && std::chrono::duration_cast<std::chrono::seconds>(now - lastCacheTime_).count() < 3) {
        return cachedUsers_;
    }
    cachedUsers_ = Database::Instance().GetAllUsers();
    lastCacheTime_ = now;
    return cachedUsers_;
}

bool UserManager::Authenticate(const std::string& username, const std::string& password,
                                const std::string& clientIP, UserInfo& user) {
    if (Database::Instance().IsIPBanned(clientIP)) {
        std::cerr << "[AUTH-FAIL] IP banned: " << clientIP << std::endl;
        return false;
    }

    // 检查全局免认证 IP 列表
    if (Database::Instance().IsNoAuthIP(clientIP)) {
        user.id = 0;
        user.username = "no-auth";
        user.enabled = true;
        return true;
    }

    auto allUsers = GetCachedUsers(); // 使用内存缓存，避免每次握手全量扫盘
    std::string currentDate = Utils::GetCurrentDate();
    bool isExplicit = !username.empty();

    // 如果显式指定了用户名，但该用户被禁用，直接拒绝
    if (isExplicit) {
        for (const auto& u : allUsers) {
            if (u.username == username && !u.enabled) {
                std::cerr << "[AUTH-FAIL] User disabled: " << username << std::endl;
                return false;
            }
        }
    }

    bool hasHigherPriorityPasswordUser = false;

    // 核心认证顺序：严格按用户优先级 (priority ASC, id ASC) 评估
    for (const auto& u : allUsers) {
        if (!u.enabled) continue;
        if (!u.expiryDate.empty() && currentDate > u.expiryDate) continue;

        // 校验客户端源 IP 是否属于该用户的允许范围 (如 * 或 CIDR 或单IP)
        if (!Utils::IsIPAllowed(clientIP, u.allowedIPs)) {
            continue;
        }

        // 当前用户 u 的 IP 符合要求
        if (u.password.empty()) {
            // 用户无密码：根据 IP 匹配即可
            // 若存在更高优先级的密码用户，且当前访问尚未通过密码认证，则不允许降级穿透至免密用户
            if (hasHigherPriorityPasswordUser) {
                std::cerr << "[AUTH-FAIL] Blocked from falling through to no-password user '" << u.username
                          << "' because higher-priority password user exists for IP: " << clientIP << std::endl;
                if (isExplicit) Database::Instance().RecordAuthFailure(clientIP);
                return false;
            }

            // 流量配额检验
            if (!CheckTrafficLimit(u.id)) {
                std::cerr << "[AUTH-FAIL] Traffic limit exceeded for no-password user: " << u.username << std::endl;
                continue;
            }

            user = u;
            Database::Instance().ClearAuthFailure(clientIP);
            std::cerr << "[AUTH-OK] Priority Match (No-Password): " << u.username << " from " << clientIP << std::endl;
            return true;
        } else {
            // 用户有密码：只要采用密码认证方式都需密码正确
            if (!isExplicit) {
                // 客户端未提供凭据，但该 IP 命中了更高优先级的密码用户，必须要求密码认证，不能直接放行
                std::cerr << "[AUTH-REQUIRED] Password user '" << u.username
                          << "' has higher priority for IP: " << clientIP << std::endl;
                return false;
            }

            // 客户端提供了用户名和密码
            if (u.username == username) {
                if (u.password != password) {
                    std::cerr << "[AUTH-FAIL] Password mismatch for " << username << std::endl;
                    Database::Instance().RecordAuthFailure(clientIP);
                    return false;
                }
                if (!CheckTrafficLimit(u.id)) {
                    std::cerr << "[AUTH-FAIL] Traffic limit exceeded for " << username << std::endl;
                    return false;
                }

                user = u;
                Database::Instance().ClearAuthFailure(clientIP);
                std::cerr << "[AUTH-OK] Explicit Auth SUCCESS for user: " << username << " from " << clientIP << std::endl;
                return true;
            } else {
                // 提供的凭据不是该用户，标记存在更高优先级的密码用户，继续查看后续用户
                hasHigherPriorityPasswordUser = true;
                continue;
            }
        }
    }

    if (isExplicit) {
        std::cerr << "[AUTH-FAIL] User not matched or authentication failed for: " << username << " from " << clientIP << std::endl;
        Database::Instance().RecordAuthFailure(clientIP);
    }
    return false;
}

bool UserManager::AuthenticateByIP(const std::string& clientIP, UserInfo& user) {
    return Authenticate("", "", clientIP, user);
}

bool UserManager::CheckTrafficLimit(int userId) {
    if (userId <= 0) return true;

    UserInfo user;
    if (!Database::Instance().GetUserById(userId, user)) return false;

    // 月度配额检查
    if (user.monthlyLimit > 0) {
        int64_t used = Database::Instance().GetUserMonthlyTraffic(userId);
        if (used >= user.monthlyLimit) {
            return false;
        }
    }

    // 每日配额检查
    if (user.dailyLimit > 0) {
        int64_t used = Database::Instance().GetUserDailyTraffic(userId);
        if (used >= user.dailyLimit) {
            return false;
        }
    }

    return true;
}

bool UserManager::CheckIPAllowed(int userId, const std::string& clientIP) {
    UserInfo user;
    if (!Database::Instance().GetUserById(userId, user)) return false;
    return Utils::IsIPAllowed(clientIP, user.allowedIPs);
}

bool UserManager::IsTargetAllowed(const std::string& targetIP, const std::string& targetDomain,
                                 const std::string& allowedTargets) {
    if (allowedTargets.empty() || allowedTargets == "*") return true;

    auto targets = Utils::Split(allowedTargets, ',');
    for (auto& item : targets) {
        item = Utils::Trim(item);
        if (item.empty()) continue;
        if (item == "*") return true;
        if (!targetDomain.empty() && item == targetDomain) return true;
        if (!targetIP.empty() && Utils::MatchCIDR(targetIP, item)) return true;
    }
    return false;
}
